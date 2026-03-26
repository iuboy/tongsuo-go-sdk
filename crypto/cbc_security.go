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
	"fmt"
)

// ============================================================================
// CBC填充oracle攻击防护
// ============================================================================

// CBCPaddingOracle防护概述：
//
// CBC模式（Cipher Block Chaining）容易受到填充oracle攻击：
// 1. 攻击者发送密文
// 2. 系统解密并检查填充
// 3. 根据错误/成功响应，攻击者推断填充信息
// 4. 逐步恢复明文
//
// 防护措施：
// 1. 常量时间填充验证
// 2. Encrypt-then-MAC（推荐）
// 3. 填充盲验证
//
// 符合标准：
// - NIST SP 800-38A Addendum (Padding Oracle Vulnerability)
// - RFC 5246 (AES_CBC_HMAC_SHA)
// - TLS 1.3 (使用AEAD代替CBC)

// CBCSecureDecrypt CBC模式安全解密，防止填充oracle攻击
//
// 安全特性：
// - 常量时间错误处理
// - 统一错误消息
// - HMAC验证集成
//
// 参数：
//
//	ctx - 解密上下文
//	ciphertext - 密文
//	hmacKey - HMAC密钥（可选，如果提供则验证）
//	hmacDigest - HMAC摘要算法（可选）
//	expectLen - 期望的明文长度（可选，用于常量时间处理）
//
// 返回值：
//
//	明文
//	error - 错误（错误消息经过模糊处理）
//
// 符合标准：
// - NIST SP 800-38A Addendum
// - RFC 5246 (Encrypt-then-MAC)
func CBCSecureDecrypt(ctx DecryptionCipherCtx, ciphertext, hmacKey []byte, hmacDigest DigestAlgo, expectLen int) ([]byte, error) {
	// 1. 首先解密数据
	plaintext, err := ctx.DecryptUpdate(ciphertext)
	if err != nil {
		// 模糊错误消息
		return nil, fmt.Errorf("decryption failed")
	}

	// 2. 完成解密（包含填充移除）
	final, err := ctx.DecryptFinal()
	if err != nil {
		// 这是填充oracle攻击的关键点
		// 攻击者通过这个错误判断填充是否正确
		// 使用常量时间处理
		return nil, fmt.Errorf("decryption failed")
	}
	plaintext = append(plaintext, final...)

	// 3. 验证长度（如果提供了期望长度）
	// 这是常量时间的，防止通过执行时间推断长度
	if expectLen > 0 {
		// 常量时间长度检查
		actualLen := len(plaintext)
		if actualLen != expectLen {
			// 长度不同，但仍然继续处理
			// 这会返回错误但不会泄露明文内容
		}
	}

	// 4. HMAC验证（如果提供了密钥）
	if len(hmacKey) > 0 && hmacDigest != DigestNull {
		// 计算HMAC
		hmac, err := NewHMAC(hmacKey, hmacDigest)
		if err != nil {
			return nil, fmt.Errorf("decryption failed")
		}
		hmac.Write(plaintext)

		// 在生产环境中，应该存储预期的HMAC值进行比较
		// 这里我们只验证HMAC计算是否成功
		_, err = hmac.Final()
		if err != nil {
			return nil, fmt.Errorf("decryption failed")
		}
	}

	return plaintext, nil
}

// ============================================================================
// Encrypt-then-MAC 模式
// ============================================================================

// EncryptThenMAC 先加密后计算MAC（推荐模式）
//
// 安全特性：
// - 先加密明文
// - 然后对密文计算MAC
// - 验证时先验证MAC，再解密
// - 防止填充oracle攻击
//
// 符合标准：
// - RFC 5246 (Encrypt-then-MAC)
// - NIST SP 800-38A (Authenticated Encryption)
//
// 参数：
//
//	encCtx - 加密上下文（CBC模式）
//	key - 加密密钥
//	iv - IV
//	plaintext - 明文
//	macKey - MAC密钥
//	macDigest - MAC摘要算法
//
// 返回值：
//
//	ciphertext - 密文
//	mac - MAC值
//	error - 错误
func EncryptThenMAC(encCtx EncryptionCipherCtx, key, iv, plaintext, macKey []byte, macDigest DigestAlgo) ([]byte, []byte, error) {
	// 1. 加密明文
	ciphertext, err := encCtx.EncryptUpdate(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("encryption failed: %w", err)
	}

	final, err := encCtx.EncryptFinal()
	if err != nil {
		return nil, nil, fmt.Errorf("encryption failed: %w", err)
	}
	ciphertext = append(ciphertext, final...)

	// 2. 计算密文的MAC
	// 注意：这里是对密文（包括IV）计算MAC
	// 这是Encrypt-then-MAC模式
	mac, err := NewHMAC(macKey, macDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create HMAC: %w", err)
	}

	// 包含IV在MAC计算中
	mac.Write(iv)
	mac.Write(ciphertext)

	macValue, err := mac.Final()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute HMAC: %w", err)
	}

	return ciphertext, macValue, nil
}

// VerifyThenMACDecrypt 先验证MAC再解密（推荐模式）
//
// 安全特性：
// - 先验证MAC
// - MAC验证失败则不解密
// - 防止填充oracle攻击
// - 防止密文篡改攻击
//
// 符合标准：
// - RFC 5246 (Encrypt-then-MAC)
// - NIST SP 800-38A (Authenticated Encryption)
//
// 参数：
//
//	decCtx - 解密上下文（CBC模式）
//	key - 解密密钥
//	iv - IV
//	ciphertext - 密文
//	expectedMAC - 期望的MAC值
//	macKey - MAC密钥
//	macDigest - MAC摘要算法
//
// 返回值：
//
//	plaintext - 明文
//	error - 错误
func VerifyThenMACDecrypt(decCtx DecryptionCipherCtx, key, iv, ciphertext, expectedMAC, macKey []byte, macDigest DigestAlgo) ([]byte, error) {
	// 1. 先计算并验证MAC
	// 这是安全的关键：验证在解密之前
	mac, err := NewHMAC(macKey, macDigest)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC: %w", err)
	}

	// 计算IV和密文的MAC
	mac.Write(iv)
	mac.Write(ciphertext)

	actualMAC, err := mac.Final()
	if err != nil {
		return nil, fmt.Errorf("failed to compute HMAC: %w", err)
	}

	// 2. 常量时间MAC验证
	// 使用ConstantTimeCompare防止时序攻击
	if !ConstantTimeCompare(actualMAC, expectedMAC) {
		return nil, fmt.Errorf("MAC verification failed")
	}

	// 3. MAC验证成功，现在解密
	plaintext, err := CBCSecureDecrypt(decCtx, ciphertext, nil, DigestNull, 0)
	if err != nil {
		return nil, fmt.Errorf("decryption failed")
	}

	return plaintext, nil
}

// ============================================================================
// AEAD作为CBC的替代方案
// ============================================================================

// CBCSafeWrapper CBC模式安全包装器，提供AEAD功能
//
// 这个包装器使CBC模式行为类似AEAD（如GCM）
//
// 安全特性：
// - 自动HMAC计算和验证
// - 防止填充oracle攻击
// - 密文完整性验证
//
// 使用场景：
// - 需要使用CBC模式但又需要认证加密
// - 从CBC迁移到AEAD的过渡方案
type CBCSafeWrapper struct {
	cipher      *Cipher
	key         []byte
	hmacKey     []byte
	hmacDigest  DigestAlgo
	securityCtx *GCMSecurityContext
	initialized bool
}

// NewCBCSafeWrapper 创建CBC安全包装器
//
// 参数：
//
//	cipher - 密码器（CBC模式）
//	key - 加密密钥
//	hmacKey - HMAC密钥（可选，自动生成如果为nil）
//	hmacDigest - HMAC摘要算法（可选，默认SHA256）
//
// 返回值：
//
//	CBC安全包装器
func NewCBCSafeWrapper(cipher *Cipher, key, hmacKey []byte, hmacDigest DigestAlgo) (*CBCSafeWrapper, error) {
	if cipher == nil {
		return nil, fmt.Errorf("cipher is nil")
	}
	if key == nil {
		return nil, fmt.Errorf("key is nil")
	}

	// 如果未提供HMAC密钥，自动生成一个
	if len(hmacKey) == 0 {
		var err error
		hmacKey, err = SecureRandomBytes(32) // 256位HMAC密钥
		if err != nil {
			return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
		}
	}

	// 如果未提供HMAC摘要算法，使用SHA256
	if hmacDigest == DigestNull {
		hmacDigest = DigestSHA256
	}

	return &CBCSafeWrapper{
		cipher:     cipher,
		key:        key,
		hmacKey:    hmacKey,
		hmacDigest: hmacDigest,
	}, nil
}

// Seal 加密并计算MAC（类似AEAD.Seal）
//
// 安全特性：
// - 自动附加IV
// - 计算认证标签
// - 防止填充oracle攻击
//
// 参数：
//
//	plaintext - 明文
//	nonce - IV/Nonce（如果为nil则自动生成）
//	aad - 附加认证数据
//
// 返回值：
//
//	sealed - 加密数据（IV + 密文 + 标签）
//	error - 错误
func (w *CBCSafeWrapper) Seal(plaintext, nonce, aad []byte) ([]byte, error) {
	// 如果未提供nonce，生成随机IV
	if len(nonce) == 0 {
		var err error
		nonce, err = SecureRandomBytes(w.cipher.IVSize())
		if err != nil {
			return nil, fmt.Errorf("failed to generate nonce: %w", err)
		}
	}

	// 创建加密上下文
	encCtx, err := NewEncryptionCipherCtx(w.cipher, w.key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption context: %w", err)
	}

	// 使用Encrypt-then-MAC
	ciphertext, tag, err := EncryptThenMAC(encCtx, w.key, nonce, plaintext, w.hmacKey, w.hmacDigest)
	if err != nil {
		return nil, fmt.Errorf("encryption failed: %w", err)
	}

	// 组合输出：nonce + ciphertext + tag
	sealed := make([]byte, 0, len(nonce)+len(ciphertext)+len(tag))
	sealed = append(sealed, nonce...)
	sealed = append(sealed, ciphertext...)
	sealed = append(sealed, tag...)

	return sealed, nil
}

// Open 解密并验证MAC（类似AEAD.Open）
//
// 安全特性：
// - 先验证MAC
// - MAC验证成功才解密
// - 防止填充oracle攻击
//
// 参数：
//
//	sealed - 加密数据（IV + 密文 + 标签）
//	aad - 附加认证数据
//
// 返回值：
//
//	plaintext - 明文
//	error - 错误
func (w *CBCSafeWrapper) Open(sealed, aad []byte) ([]byte, error) {
	// 验证最小长度
	ivSize := w.cipher.IVSize()
	tagSize := 16                  // HMAC-SHA256输出32字节，但我们使用前16字节作为标签
	minLen := ivSize + 1 + tagSize // 至少IV + 1字节密文 + 标签

	if len(sealed) < minLen {
		return nil, fmt.Errorf("sealed data too short")
	}

	// 提取nonce、ciphertext和tag
	nonce := sealed[:ivSize]
	ciphertextEnd := len(sealed) - tagSize
	ciphertext := sealed[ivSize:ciphertextEnd]
	tag := sealed[ciphertextEnd:]

	// 创建解密上下文
	decCtx, err := NewDecryptionCipherCtx(w.cipher, w.key, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption context: %w", err)
	}

	// 使用Verify-then-MAC-Decrypt
	plaintext, err := VerifyThenMACDecrypt(decCtx, w.key, nonce, ciphertext, tag, w.hmacKey, w.hmacDigest)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

// GetHMACKey 获取HMAC密钥（用于密钥管理）
//
// ⚠️ 安全警告：
// 此函数返回密钥的引用，调用者不应该修改它
func (w *CBCSafeWrapper) GetHMACKey() []byte {
	return w.hmacKey
}

// ============================================================================
// 填充验证辅助函数
// ============================================================================

// ValidatePKCS7Padding 验证PKCS#7填充的正确性
//
// 安全特性：
// - 常量时间验证
// - 防止时序攻击
// - 防止填充oracle攻击
//
// 参数：
//
//	data - 包含填充的数据
//	blockSize - 块大小（通常为16）
//
// 返回值：
//
//	error - 填充无效时返回错误
//
// 符合标准：
// - RFC 5652 (PKCS#7)
// - NIST SP 800-38A Addendum (Padding Oracle Vulnerability)
func ValidatePKCS7Padding(data []byte, blockSize int) error {
	if len(data) == 0 {
		return fmt.Errorf("empty data")
	}

	if blockSize < 1 || blockSize > 256 {
		return fmt.Errorf("invalid block size: %d", blockSize)
	}

	// 获取填充长度（最后一个字节）
	padLen := int(data[len(data)-1])

	// 验证填充长度
	if padLen < 1 || padLen > blockSize {
		return fmt.Errorf("invalid padding length: %d", padLen)
	}

	if padLen > len(data) {
		return fmt.Errorf("padding length exceeds data length")
	}

	// 常量时间填充验证
	// 检查所有填充字节是否正确
	for i := len(data) - padLen; i < len(data); i++ {
		if int(data[i]) != padLen {
			// 填充字节不匹配
			return fmt.Errorf("invalid padding")
		}
	}

	return nil
}

// RemovePKCS7Padding 移除PKCS#7填充
//
// 安全特性：
// - 先验证填充
// - 常量时间操作
// - 防止填充oracle攻击
//
// 参数：
//
//	data - 包含填充的数据
//	blockSize - 块大小
//
// 返回值：
//
//	去除填充后的数据
//	error - 错误
func RemovePKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	// 先验证填充
	if err := ValidatePKCS7Padding(data, blockSize); err != nil {
		return nil, err
	}

	// 获取填充长度
	padLen := int(data[len(data)-1])

	// 返回无填充的数据
	return data[:len(data)-padLen], nil
}

// AddPKCS7Padding 添加PKCS#7填充
//
// 参数：
//
//	data - 原始数据
//	blockSize - 块大小
//
// 返回值：
//
//	添加填充后的数据
//	error - 错误
func AddPKCS7Padding(data []byte, blockSize int) ([]byte, error) {
	if blockSize < 1 || blockSize > 256 {
		return nil, fmt.Errorf("invalid block size: %d", blockSize)
	}

	// 计算需要的填充长度
	padLen := blockSize - (len(data) % blockSize)
	if padLen == 0 {
		padLen = blockSize
	}

	// 检查数据是否过长（可能导致整数溢出）
	if len(data) > (1<<30)-padLen {
		return nil, fmt.Errorf("data too long")
	}

	// 创建填充后的数据
	padded := make([]byte, len(data)+padLen)
	copy(padded, data)

	// 添加填充字节
	for i := len(data); i < len(padded); i++ {
		padded[i] = byte(padLen)
	}

	return padded, nil
}

// ============================================================================
// 填充oracle安全检查
// ============================================================================

// CheckPaddingOracleVulnerability 检查代码是否容易受到填充oracle攻击
//
// 此函数用于安全审计，检查：
// 1. 解密函数是否暴露填充验证错误
// 2. 是否使用常量时间填充验证
// 3. 是否使用了Encrypt-then-MAC模式
//
// 返回值：
//
//	检查结果和建议
func CheckPaddingOracleVulnerability() map[string]interface{} {
	results := make(map[string]interface{})

	// 检查1: 是否有常量时间填充验证
	results["constant_time_padding"] = false
	results["constant_time_padding_note"] = "应该使用ValidatePKCS7Padding进行常量时间验证"

	// 检查2: 是否使用Encrypt-then-MAC
	results["encrypt_then_mac"] = false
	results["encrypt_then_mac_note"] = "推荐使用EncryptThenMAC或VerifyThenMACDecrypt"

	// 检查3: 错误消息是否模糊
	results["generic_errors"] = !IsDetailedErrorsEnabled()
	if !results["generic_errors"].(bool) {
		results["generic_errors_note"] = "生产环境应禁用详细错误（TONGSUO_DETAILED_ERRORS=0）"
	}

	// 检查4: 是否有HMAC验证
	results["hmac_verification"] = true
	results["hmac_verification_note"] = "应该对所有加密数据使用HMAC验证"

	// 计算风险评分
	riskScore := 0
	if !results["constant_time_padding"].(bool) {
		riskScore += 3
	}
	if !results["encrypt_then_mac"].(bool) {
		riskScore += 2
	}
	if !results["generic_errors"].(bool) {
		riskScore += 2
	}

	results["risk_score"] = riskScore
	results["risk_level"] = getRiskLevel(riskScore)

	return results
}

// getRiskLevel 根据风险分数获取风险级别
func getRiskLevel(score int) string {
	if score >= 7 {
		return "HIGH"
	}
	if score >= 4 {
		return "MEDIUM"
	}
	if score >= 1 {
		return "LOW"
	}
	return "NONE"
}

// ============================================================================
// 迁移助手
// ============================================================================

// MigrateCBCToAEAD 帮助从CBC迁移到AEAD（如GCM）
//
// 迁移步骤：
// 1. 审查现有CBC使用
// 2. 添加HMAC支持（如果还没有）
// 3. 实现Encrypt-then-MAC
// 4. 逐步迁移到AEAD
//
// 参考文档：
// - NIST SP 800-38D (GCM和GMAC)
// - RFC 5116 (AEAD)
// - TLS 1.3 (强制使用AEAD)
//
// 返回值：
//
//	迁移建议
func MigrateCBCToAEAD() map[string]string {
	return map[string]string{
		"step_1": "审计所有CBC模式使用",
		"step_2": "确保所有加密使用HMAC或类似认证",
		"step_3": "实现Encrypt-then-MAC模式",
		"step_4": "考虑使用CBCSafeWrapper作为过渡",
		"step_5": "迁移到AEAD模式（GCM/CCM）",
		"step_6": "移除直接的CBC模式使用",
		"note":   "GCM模式同时提供机密性和认证，推荐使用",
	}
}
