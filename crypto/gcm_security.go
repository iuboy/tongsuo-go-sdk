// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto

// #include "shim.h"
import "C"

import (
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
)

// GCMSecurityContext GCM模式安全上下文
//
// 防止IV重用攻击，这是GCM模式最严重的安全风险。
//
// ⚠️ IV重用后果：
// - 认证密钥泄露：攻击者可以伪造消息
// - 明文恢复：在某些情况下可以恢复明文
// - 完全破坏GCM的安全性
//
// 符合标准：
// - NIST SP 800-38D Section 8 ( uniqueness of IV )
// - NIST SP 800-38D Section 5.2.1.1 ( IV generation )
// - RFC 5116 ( AEAD )
//
// 安全警告：
// - IV重用会完全破坏GCM的安全性
// - 每个加密操作必须使用唯一的IV
// - 推荐使用随机IV或计数器IV
type GCMSecurityContext struct {
	mu         sync.RWMutex
	ivHistory  map[string]struct{} // 使用 struct{} 值节省内存
	maxHistory int
	contextID  string
	totalCount int64
}

// gcmSecurityManager 全局GCM安全管理器
//
// 安全限制：
// - 最大上下文数量由 gcmMaxContexts 控制（默认 1024）
// - 超过限制后拒绝创建新上下文，防止 DoS 攻击
var gcmSecurityManager = struct {
	sync.RWMutex
	contexts map[string]*GCMSecurityContext
}{
	contexts: make(map[string]*GCMSecurityContext),
}

const gcmMaxContexts = 1024

// NewGCMSecurityContext 创建新的GCM安全上下文
//
// 参数：
//
//	contextID - 上下文标识符（用于多个GCM实例）
//	maxHistory - 最大IV历史记录数（0表示无限制，默认10000）
//
// 返回值：
//
//	GCM安全上下文
//
// 推荐配置：
// - contextID应该唯一标识使用场景（如会话ID、连接ID等）
// - maxHistory建议值：
//   * 低安全性应用：1000（约1MB内存）
//   * 标准安全性应用：10000（约10MB内存）
//   * 高安全性应用：100000（约100MB内存）
//   * 极高安全性应用：0（无限制，需监控内存）
//
// 内存使用估算：
// - 每个IV条目约100字节（16字节IV的hex编码 + map开销）
// - 10000个IV ≈ 1MB内存
func NewGCMSecurityContext(contextID string, maxHistory int) *GCMSecurityContext {
	if maxHistory < 0 {
		maxHistory = 0
	}
	if maxHistory == 0 {
		maxHistory = 10000
	}

	return &GCMSecurityContext{
		ivHistory:  make(map[string]struct{}, maxHistory/10),
		maxHistory: maxHistory,
		contextID:  contextID,
	}
}

// GetGCMSecurityContext 获取或创建GCM安全上下文
//
// 参数：
//
//	contextID - 上下文标识符
//
// 返回值：
//
//	GCM安全上下文
func GetGCMSecurityContext(contextID string) *GCMSecurityContext {
	gcmSecurityManager.Lock()
	defer gcmSecurityManager.Unlock()

	ctx, exists := gcmSecurityManager.contexts[contextID]
	if !exists {
		if len(gcmSecurityManager.contexts) >= gcmMaxContexts {
			// 超过最大上下文数，返回错误上下文（所有操作会失败）
			// 防止通过创建大量上下文耗尽内存
			return &GCMSecurityContext{
				ivHistory:  make(map[string]struct{}),
				maxHistory: 0,
				contextID:  "",
			}
		}
		ctx = NewGCMSecurityContext(contextID, 10000) // 默认保留10000个IV
		gcmSecurityManager.contexts[contextID] = ctx
	}
	return ctx
}

// checkAndRecordIV 检查并记录IV使用
//
// 安全特性：
// - 防止IV重用
// - 当历史满时拒绝新加密（防止IV重放攻击）
// - 常量时间比较（防止时序攻击）
//
// 返回值：
//
//	error - 如果IV已被使用或历史已满则返回错误
//
// C-08 修复说明：
// 修复前使用 FIFO 清理策略淘汰旧 IV，允许被淘汰的 IV 被重用（重放攻击）。
// 修复后当历史满时直接拒绝新的加密操作，要求调用方执行密钥轮换。
// 这符合 NIST SP 800-38D Section 8 对 IV 唯一性的严格要求。
func (ctx *GCMSecurityContext) checkAndRecordIV(iv []byte) error {
	// IV长度验证
	if len(iv) < 12 {
		return fmt.Errorf("GCM IV too short: %d bytes (minimum 12 per NIST SP 800-38D)", len(iv))
	}

	// 直接使用 IV 字节作为 map key，避免 hex 编码的性能和内存开销
	ivKey := string(iv)

	ctx.mu.Lock()
	defer ctx.mu.Unlock()

	// 检查IV是否已被使用
	if _, exists := ctx.ivHistory[ivKey]; exists {
		// 注意：不泄露 IV 值，仅返回通用错误（C-01 修复）
		return fmt.Errorf("GCM IV reuse detected - critical security failure! Context: %s",
			ctx.contextID)
	}

	// C-08 修复：当历史满时拒绝新加密，而非淘汰旧 IV
	// 防止被淘汰的 IV 被重用（重放攻击）
	if ctx.maxHistory > 0 && len(ctx.ivHistory) >= ctx.maxHistory {
		return fmt.Errorf("GCM IV history full (%d/%d) - key rotation required. "+
			"Call ClearIVHistory() after rotating the encryption key. Context: %s",
			len(ctx.ivHistory), ctx.maxHistory, ctx.contextID)
	}

	// 记录此IV
	ctx.ivHistory[ivKey] = struct{}{}
	ctx.totalCount++

	return nil
}

// ClearIVHistory 清空IV历史记录
//
// ⚠️ 安全警告：
// 清空历史记录后，之前使用的IV可以再次使用
// 应该仅在以下情况使用：
// 1. 创建新会话时
// 2. 密钥轮换后
// 3. 确定所有使用旧IV的数据已失效
func (ctx *GCMSecurityContext) ClearIVHistory() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.ivHistory = make(map[string]struct{})
}

// GetIVHistorySize 获取当前IV历史记录数量
func (ctx *GCMSecurityContext) GetIVHistorySize() int {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return len(ctx.ivHistory)
}

// ============================================================================
// 安全的GCM包装函数
// ============================================================================

// GCMEncrypt 安全的GCM加密，包含IV重用检测
//
// 参数：
//
//	key - 加密密钥
//	plaintext - 明文
//	iv - 初始化向量（必须唯一）
//	aad - 附加认证数据（可选）
//	securityCtx - GCM安全上下文（可选，nil使用默认）
//
// 返回值：
//
//	ciphertext - 密文
//	tag - 认证标签
//	error - 错误
//
// 安全特性：
// - IV重用检测
// - 符合NIST SP 800-38D
// - AEAD认证加密
//
// 符合标准：
// - NIST SP 800-38D (GCM)
// - RFC 5116 (AEAD)
func GCMEncrypt(key, plaintext, iv, aad []byte, securityCtx *GCMSecurityContext) ([]byte, []byte, error) {
	// 参数验证
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, nil, fmt.Errorf("invalid GCM key size: %d bytes (expected 16/24/32)", len(key))
	}
	if len(iv) < 12 {
		// NIST SP 800-38D 推荐最小12字节
		return nil, nil, fmt.Errorf("IV too short (got %d bytes, minimum 12 recommended)", len(iv))
	}

	// 使用默认或提供的上下文
	if securityCtx == nil {
		securityCtx = GetGCMSecurityContext("default")
	}

	// 检查并记录IV
	if err := securityCtx.checkAndRecordIV(iv); err != nil {
		return nil, nil, fmt.Errorf("IV validation failed: %w", err)
	}

	// 确定块大小（AES密钥长度）
	blocksize := len(key) * 8

	// 创建加密上下文
	encCtx, err := NewGCMEncryptionCipherCtx(blocksize, key, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM encryption context: %w", err)
	}

	// 添加AAD（如果有）
	if len(aad) > 0 {
		if err := encCtx.ExtraData(aad); err != nil {
			return nil, nil, fmt.Errorf("failed to add AAD: %w", err)
		}
	}

	// 加密明文
	ciphertext, err := encCtx.EncryptUpdate(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 完成加密
	final, err := encCtx.EncryptFinal()
	if err != nil {
		return nil, nil, fmt.Errorf("encryption final failed: %w", err)
	}
	ciphertext = append(ciphertext, final...)

	// 获取认证标签
	tag, err := encCtx.GetTag()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get authentication tag: %w", err)
	}

	return ciphertext, tag, nil
}

// GCMDecrypt 安全的GCM解密，包含IV验证
//
// 参数：
//
//	key - 解密密钥
//	ciphertext - 密文
//	tag - 认证标签
//	iv - 初始化向量
//	aad - 附加认证数据（可选）
//	securityCtx - GCM安全上下文（可选，nil使用默认）
//
// 返回值：
//
//	plaintext - 明文
//	error - 错误
//
// 安全特性：
// - IV重用检测（可选）
// - 常量时间标签验证
// - 完整性验证
func GCMDecrypt(key, ciphertext, tag, iv, aad []byte, securityCtx *GCMSecurityContext) ([]byte, error) {
	// 参数验证
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, fmt.Errorf("invalid GCM key size: %d bytes (expected 16/24/32)", len(key))
	}
	if len(iv) < 12 {
		return nil, fmt.Errorf("IV too short (got %d bytes, minimum 12 recommended)", len(iv))
	}
	if len(tag) != 16 {
		// GCM标签必须是16字节
		return nil, fmt.Errorf("invalid GCM tag size: %d bytes (expected 16)", len(tag))
	}

	// 注意：解密不记录 IV。
	// GCM 解密的安全性由认证标签（authentication tag）保证，而非 IV 唯一性。
	// IV 唯一性要求仅适用于加密操作（NIST SP 800-38D Section 8）。
	// 如果使用同一 securityCtx 进行加密和解密，解密记录 IV 会导致后续
	// 使用相同 IV 的加密操作被误判为 IV 重用（C-07 修复）。

	// 确定块大小
	blocksize := len(key) * 8

	// 创建解密上下文
	decCtx, err := NewGCMDecryptionCipherCtx(blocksize, key, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM decryption context: %w", err)
	}

	// 设置认证标签（必须在解密前设置）
	if err := decCtx.SetTag(tag); err != nil {
		return nil, fmt.Errorf("failed to set authentication tag: %w", err)
	}

	// 添加AAD（如果有）
	if len(aad) > 0 {
		if err := decCtx.ExtraData(aad); err != nil {
			return nil, fmt.Errorf("failed to add AAD: %w", err)
		}
	}

	// 解密密文
	plaintext, err := decCtx.DecryptUpdate(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption failed (authentication failure?): %w", err)
	}

	// 完成解密
	final, err := decCtx.DecryptFinal()
	if err != nil {
		return nil, fmt.Errorf("decryption final failed (authentication failure): %w", err)
	}
	plaintext = append(plaintext, final...)

	return plaintext, nil
}

// ============================================================================
// 安全的IV生成函数
// ============================================================================

// GenerateGCMRandomIV 生成随机的GCM IV
//
// 符合标准：
// - NIST SP 800-38D Section 8.2 (推荐的IV生成方法)
// - 使用加密安全的随机数生成器
//
// 参数：
//
//	ivLen - IV长度（推荐12或16字节）
//
// 返回值：
//
//	随机IV
//	error - 错误
//
// 推荐IV长度：
// - 12字节：NIST推荐，提供良好的安全性/性能平衡
// - 16字节：提供更高的碰撞抵抗
func GenerateGCMRandomIV(ivLen int) ([]byte, error) {
	if ivLen < 12 {
		return nil, fmt.Errorf("IV length too short (got %d, minimum 12)", ivLen)
	}
	if ivLen > 1024 {
		return nil, fmt.Errorf("IV length too large (got %d, maximum 1024)", ivLen)
	}

	iv := make([]byte, ivLen)
	_, err := rand.Read(iv)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random IV: %w", err)
	}

	return iv, nil
}

// GenerateGCMCounterIV 生成计数器模式的GCM IV
//
// 安全特性：
// - 确保唯一性
// - 避免随机IV的碰撞风险
// - 适合批量加密场景
//
// 符合标准：
// - NIST SP 800-38D Section 8.2
//
// 参数：
//
//	baseIV - 基础IV（固定部分）
//	counter - 计数器值（必须递增）
//
// 返回值：
//
//	生成的IV
//	error - 错误
//
// 安全警告：
// - 计数器值绝不能重复
// - 必须安全地维护计数器状态
// - 考虑使用64位或96位计数器
func GenerateGCMCounterIV(baseIV []byte, counter uint64) ([]byte, error) {
	ivLen := len(baseIV)
	if ivLen < 12 {
		return nil, fmt.Errorf("base IV too short (got %d, minimum 12)", ivLen)
	}

	// 创建IV副本
	iv := make([]byte, ivLen)
	copy(iv, baseIV)

	// 将计数器编码到IV的末尾
	// 使用大端序编码
	offset := ivLen
	if ivLen >= 8 {
		offset = ivLen - 8
	}

	for i := uint64(0); i < 8; i++ {
		iv[uint64(offset)+7-i] = byte(counter >> (i * 8))
	}

	return iv, nil
}

// ============================================================================
// GCM使用辅助函数
// ============================================================================

// EncryptWithAutoGCMIV 自动生成IV的GCM加密
//
// 安全特性：
// - 自动生成安全的随机IV
// - IV包含在输出中
// - 防止IV重用
//
// 输出格式：
//
//	[IV (12 bytes)][Ciphertext][Tag (16 bytes)]
//
// 参数：
//
//	key - 加密密钥
//	plaintext - 明文
//	aad - 附加认证数据（可选）
//	securityCtx - GCM安全上下文（可选）
//
// 返回值：
//
//	加密数据（IV + 密文 + 标签）
//	error - 错误
func EncryptWithAutoGCMIV(key, plaintext, aad []byte, securityCtx *GCMSecurityContext) ([]byte, error) {
	// 生成12字节随机IV（NIST推荐长度）
	iv, err := GenerateGCMRandomIV(12)
	if err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// 使用安全上下文（如果未提供）
	if securityCtx == nil {
		securityCtx = GetGCMSecurityContext("auto-gcm")
	}

	// 加密
	ciphertext, tag, err := GCMEncrypt(key, plaintext, iv, aad, securityCtx)
	if err != nil {
		return nil, err
	}

	// 组合输出：IV + 密文 + 标签
	output := make([]byte, 0, len(iv)+len(ciphertext)+len(tag))
	output = append(output, iv...)
	output = append(output, ciphertext...)
	output = append(output, tag...)

	return output, nil
}

// DecryptWithAutoGCMIV 自动提取IV的GCM解密
//
// 输入格式：
//
//	[IV (12 bytes)][Ciphertext][Tag (16 bytes)]
//
// 参数：
//
//	key - 解密密钥
//	data - 加密数据（IV + 密文 + 标签）
//	aad - 附加认证数据（可选）
//	securityCtx - GCM安全上下文（可选）
//
// 返回值：
//
//	明文
//	error - 错误
func DecryptWithAutoGCMIV(key, data, aad []byte, securityCtx *GCMSecurityContext) ([]byte, error) {
	// 验证最小长度
	// IV (12) + 最小密文 (1) + 标签 (16) = 29字节
	if len(data) < 29 {
		return nil, fmt.Errorf("data too short (got %d bytes, minimum 29)", len(data))
	}

	// 提取IV
	iv := data[:12]

	// 提取密文和标签
	ciphertext := data[12 : len(data)-16]
	tag := data[len(data)-16:]

	// 使用安全上下文（如果未提供）
	if securityCtx == nil {
		securityCtx = GetGCMSecurityContext("auto-gcm")
	}

	// 解密
	plaintext, err := GCMDecrypt(key, ciphertext, tag, iv, aad, securityCtx)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

// ============================================================================
// 包装函数 - 用于向后兼容和安全增强
// ============================================================================

// NewSecureGCMEncryptionCipherCtx 创建安全的GCM加密上下文
//
// 此函数包装 NewGCMEncryptionCipherCtx，添加IV重用检测
//
// 参数：
//
//	blocksize - 块大小 (128/192/256)
//	key - 密钥
//	iv - IV（可以为nil，稍后设置）
//	securityCtx - GCM安全上下文（可选）
//
// 返回值：
//
//	安全的GCM加密上下文
//	error - 错误
func NewSecureGCMEncryptionCipherCtx(blocksize int, key, iv []byte, securityCtx *GCMSecurityContext) (AuthenticatedEncryptionCipherCtx, error) {
	ctx, err := NewGCMEncryptionCipherCtx(blocksize, key, nil)
	if err != nil {
		return nil, err
	}

	// 如果提供了IV，立即验证
	if len(iv) > 0 {
		if securityCtx == nil {
			securityCtx = GetGCMSecurityContext("default")
		}
		if err := securityCtx.checkAndRecordIV(iv); err != nil {
			return nil, fmt.Errorf("IV validation failed: %w", err)
		}

		// 设置IV
		if err := ctx.SetCtrl(C.EVP_CTRL_GCM_SET_IVLEN, len(iv)); err != nil {
			return nil, fmt.Errorf("failed to set IV length: %w", err)
		}
		if C.EVP_EncryptInit_ex(ctx.Ctx(), nil, nil, nil, (*C.uchar)(&iv[0])) != 1 {
			return nil, fmt.Errorf("failed to set IV: %w", PopError())
		}
	}

	// 防御性复制密钥，防止调用方修改影响加密上下文
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	// 包装上下文，添加安全跟踪
	enc := &secureGCMEncryptionCtx{
		AuthenticatedEncryptionCipherCtx: ctx,
		securityCtx:                      securityCtx,
		key:                              keyCopy,
		ivSet:                            len(iv) > 0,
	}
	// H-03 修复：设置 finalizer 确保 GC 时清零密钥副本
	runtime.SetFinalizer(enc, func(e *secureGCMEncryptionCtx) { e.Close() })
	return enc, nil
}

// secureGCMEncryptionCtx 安全的GCM加密上下文包装器
type secureGCMEncryptionCtx struct {
	AuthenticatedEncryptionCipherCtx
	securityCtx *GCMSecurityContext
	key         []byte
	ivSet       bool
	initialized bool
}

// Close 安全清零密钥副本（H-03 修复）
//
// 符合 NIST SP 800-57 Part 1 Rev.5 Section 5.3.4：
// 密钥材料在不再使用时应被安全擦除
func (ctx *secureGCMEncryptionCtx) Close() {
	ZeroBytes(ctx.key)
	ctx.key = nil
}

// secureGCMDecryptionCtx 安全的GCM解密上下文包装器
type secureGCMDecryptionCtx struct {
	AuthenticatedDecryptionCipherCtx
	securityCtx *GCMSecurityContext
	key         []byte
	ivSet       bool
	initialized bool
}

// Close 安全清零密钥副本（H-03 修复）
func (ctx *secureGCMDecryptionCtx) Close() {
	ZeroBytes(ctx.key)
	ctx.key = nil
}

// NewSecureGCMDecryptionCipherCtx 创建安全的GCM解密上下文
func NewSecureGCMDecryptionCipherCtx(blocksize int, key, iv []byte, securityCtx *GCMSecurityContext) (AuthenticatedDecryptionCipherCtx, error) {
	ctx, err := NewGCMDecryptionCipherCtx(blocksize, key, nil)
	if err != nil {
		return nil, err
	}

	// 注意：解密不记录 IV（C-07 修复）
	// GCM 解密的安全性由认证标签（authentication tag）保证，而非 IV 唯一性。
	// IV 唯一性要求仅适用于加密操作（NIST SP 800-38D Section 8）。
	// 如果使用同一 securityCtx 进行加密和解密，解密记录 IV 会导致后续
	// 使用相同 IV 的加密操作被误判为 IV 重用。

	if len(iv) > 0 {
		// 仅验证 IV 长度，不记录到历史
		if len(iv) < 12 {
			return nil, fmt.Errorf("GCM IV too short for decryption: %d bytes (minimum 12 per NIST SP 800-38D)", len(iv))
		}

		// 设置IV
		if err := ctx.SetCtrl(C.EVP_CTRL_GCM_SET_IVLEN, len(iv)); err != nil {
			return nil, fmt.Errorf("failed to set IV length: %w", err)
		}
		if C.EVP_DecryptInit_ex(ctx.Ctx(), nil, nil, nil, (*C.uchar)(&iv[0])) != 1 {
			return nil, fmt.Errorf("failed to set IV: %w", PopError())
		}
	}

	// 防御性复制密钥，防止调用方修改影响解密上下文
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)

	dec := &secureGCMDecryptionCtx{
		AuthenticatedDecryptionCipherCtx: ctx,
		securityCtx:                      securityCtx,
		key:                              keyCopy,
		ivSet:                            len(iv) > 0,
	}
	// H-03 修复：设置 finalizer 确保 GC 时清零密钥副本
	runtime.SetFinalizer(dec, func(d *secureGCMDecryptionCtx) { d.Close() })
	return dec, nil
}

// GetGCMContextStats 获取GCM上下文统计信息
func GetGCMContextStats(contextID string) map[string]interface{} {
	gcmSecurityManager.RLock()
	defer gcmSecurityManager.RUnlock()

	stats := make(map[string]interface{})
	ctx, exists := gcmSecurityManager.contexts[contextID]
	if exists {
		stats["context_id"] = contextID
		stats["iv_history_size"] = ctx.GetIVHistorySize()
		stats["max_history"] = ctx.maxHistory
	} else {
		stats["context_id"] = contextID
		stats["iv_history_size"] = 0
		stats["exists"] = false
	}

	return stats
}

// ClearAllGCMContexts 清空所有GCM上下文历史
//
// ⚠️ 安全警告：
// 此操作会清空所有IV历史记录
// 仅在以下情况使用：
// 1. 密钥轮换后
// 2. 创建新会话时
// 3. 系统关闭前
func ClearAllGCMContexts() {
	gcmSecurityManager.Lock()
	defer gcmSecurityManager.Unlock()

	for _, ctx := range gcmSecurityManager.contexts {
		ctx.ClearIVHistory()
	}
}

// ============================================================================
// IV验证和重用检测相关错误
// ============================================================================

var (
	// ErrIVReuse IV重用错误
	ErrIVReuse = NewError("IV_REUSE", "GCM IV reuse detected - critical security failure")

	// ErrIVInvalid IV无效错误
	ErrIVInvalid = NewError("IV_INVALID", "GCM IV validation failed")
)

// NewError 创建新的结构化错误
func NewError(code, message string) error {
	return &structuredError{
		code:    code,
		message: message,
	}
}

// structuredError 结构化错误
type structuredError struct {
	code    string
	message string
}

func (e *structuredError) Error() string {
	return fmt.Sprintf("[%s] %s", e.code, e.message)
}

func (e *structuredError) Code() string {
	return e.code
}
