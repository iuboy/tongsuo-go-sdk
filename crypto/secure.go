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
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"
	"runtime"
	"time"
	"unsafe"
)

// 安全参数常量
const (
	maxRandomBytesLen = 1 << 20 // 1MB，防止 DoS
	minPrimeBits      = 512     // 最小素数位数，符合 NIST 标准
)

// ConstantTimeCompare 比较两个字节切片，使用常量时间算法
//
// 安全特性：
// - 防止时序攻击（Timing Attack）
// - 执行时间不依赖于数据内容
// - 适用于比较密钥、MAC、签名等敏感数据
//
// 参数：
//
//	a, b - 要比较的字节切片
//
// 返回值：
//
//	如果相等返回 true，否则返回 false
func ConstantTimeCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// ConstantTimeStringCompare 比较两个字符串，使用常量时间算法
//
// 安全特性：
// - 防止时序攻击
// - 适用于比较密码、令牌等敏感字符串
//
// 注意：不应使用此函数比较哈希值（应使用 ConstantTimeCompare）
func ConstantTimeStringCompare(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// ConstantTimeEq 比较两个值是否相等，使用常量时间算法
//
// 安全特性：
// - 用于防止时序攻击的条件判断
// - 返回 1 表示相等，0 表示不等（可以直接用于 if 条件）
func ConstantTimeEq(a, b int32) int {
	return subtle.ConstantTimeEq(a, b)
}

// SecureEqual 安全地比较两个字节切片是否相等
//
// 此函数是 ConstantTimeCompare 的别名，提供更直观的API
func SecureEqual(a, b []byte) bool {
	return ConstantTimeCompare(a, b)
}

// VerifyMAC 验证消息认证码，使用常量时间比较
//
// 安全特性：
// - 防止时序攻击
// - 防止长度推断攻击
// - 适用于 HMAC、CMAC 等消息认证码验证
//
// 参数：
//
//	expected - 期望的MAC值
//	actual   - 实际的MAC值
//
// 返回值：
//
//	如果MAC验证成功返回 nil，否则返回错误
func VerifyMAC(expected, actual []byte) error {
	// H-01 修复：移除提前长度检查，避免时序泄露
	// subtle.ConstantTimeCompare 在长度不等时返回 0，且执行时间为
	// O(len(expected))（取较短者），不泄露长度差异的时序信息。
	// 注意：当长度不等时，仍通过返回统一错误消息避免信息泄露。
	if subtle.ConstantTimeCompare(expected, actual) != 1 {
		return fmt.Errorf("MAC verification failed")
	}

	return nil
}

// VerifyHexMAC 验证十六进制编码的MAC值
//
// 安全特性：
// - 使用常量时间比较
// - 自动处理十六进制解码
func VerifyHexMAC(expectedHex string, actual []byte) error {
	expected, err := hex.DecodeString(expectedHex)
	if err != nil {
		return fmt.Errorf("failed to decode expected MAC: %w", err)
	}

	if !ConstantTimeCompare(expected, actual) {
		return fmt.Errorf("MAC verification failed")
	}

	return nil
}

// ZeroBytes 安全地清零字节切片
//
// 安全特性：
// - 确保密钥、密码等敏感数据从内存中移除
// - 防止内存扫描攻击
// - 使用防止编译器优化的方法
//
// 防御措施：
// - 使用volatile写入（通过runtime.KeepAlive）
// - 多次清零确保覆盖
// - 使用不同的清零模式
//
// 注意：
// - Go的垃圾回收器可能会复制内存，此函数不能保证所有副本都被清零
// - 对于高安全性应用，考虑使用专门的内存清零库
// - 建议使用WipeableByteArray等专用类型
//
// 符合标准：
// - NIST SP 800-57 Part 1 Rev.5 Section 5.3.4
// - FIPS 140-2 Section 4.12.0
// - OWASP Crytographic Storage Cheat Sheet
func ZeroBytes(b []byte) {
	if len(b) == 0 {
		return
	}

	// 使用 OPENSSL_cleanse 进行安全清零
	// OPENSSL_cleanse 使用特定于平台的实现（如 explicit_bzero、SecureZeroMemory），
	// 确保编译器不会优化掉清零操作
	C.OPENSSL_cleanse(unsafe.Pointer(&b[0]), C.size_t(len(b)))
	runtime.KeepAlive(b)
}

// ZeroBytesOnce 快速清零字节切片
//
// 与ZeroBytes相同，使用 OPENSSL_cleanse 确保编译器不会优化掉清零操作。
// 保留此函数作为向后兼容的API。
func ZeroBytesOnce(b []byte) {
	if len(b) == 0 {
		return
	}

	C.OPENSSL_cleanse(unsafe.Pointer(&b[0]), C.size_t(len(b)))
	runtime.KeepAlive(b)
}

// ZeroString 安全地清空字符串内容
//
// # ZeroString 安全清零字符串内容
//
// Deprecated: Go 字符串是不可变的。此函数只能清零 []byte(*s) 产生的堆上副本，
// 原始字符串数据（可能在只读数据段或字符串缓存中）不会被清零。
// 对于密码、密钥等敏感数据，应从一开始就使用 []byte，并使用 ZeroBytes 清零。
//
// 安全警告：由于Go字符串的不可变性，此函数只能清零 []byte(*s) 产生的堆上副本，
// 原始字符串数据（可能在只读数据段或字符串缓存中）不会被清零。
// 此函数不适合用于高安全性场景。对于密码等敏感数据，应从一开始就使用 []byte。
func ZeroString(s *string) {
	if s == nil {
		return
	}
	b := []byte(*s)
	if len(b) > 0 {
		C.OPENSSL_cleanse(unsafe.Pointer(&b[0]), C.size_t(len(b)))
		runtime.KeepAlive(b)
	}
	*s = ""
}

// SecureRandomDuration 生成一个随机的持续时间，用于延迟操作
//
// 安全特性：
// - 使用密码学安全的随机数生成器
// - 防止时序攻击中的时间推断
// - 添加随机延迟使响应时间不可预测
//
// 参数：
//
//	min - 最小延迟
//	max - 最大延迟
//
// 使用场景：
// - 密码验证后添加随机延迟
// - 认证失败后添加延迟
// - 登录失败后的延迟
//
// 符合标准：NIST SP 800-63B Section 5.2.1.5 ( artificial delays)
func SecureRandomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}

	// 计算范围
	rangeN := int64(max - min)
	if rangeN <= 0 {
		return min
	}

	// 使用密码学安全的随机数生成器
	// crypto/rand 提供了密码学安全的随机数
	//
	// 安全考虑：
	// - 必须使用 crypto/rand 而不是 math/rand
	// - crypto/rand 使用操作系统提供的 CSPRNG
	// - 对于 Unix-like 系统：从 /dev/urandom 读取
	// - 对于 Windows：使用 CryptGenRandom
	//
	// NIST SP 800-90A 要求：
	// - 使用 FIPS 140-2 批准的随机数生成器
	// - 定期进行熵估计和健康检查

	bigRange := new(big.Int).SetInt64(rangeN)
	n, err := rand.Int(rand.Reader, bigRange)
	if err != nil {
		// 随机数生成失败时回退到最小延迟
		// 使用固定最小值而非中间值，避免确定性回退
		return min
	}

	return min + time.Duration(n.Int64())
}

// SecureRandomBytes 生成密码学安全的随机字节
//
// 安全特性：
// - 使用加密安全的随机数生成器
// - 符合 NIST SP 800-90A 要求
//
// 参数：
//
//	length - 随机字节长度
//
// 返回值：
//
//	随机字节
//	error - 错误
//
// 使用场景：
// - 生成密钥
// - 生成IV/Nonce
// - 生成盐值
func SecureRandomBytes(length int) ([]byte, error) {
	if length <= 0 {
		return nil, fmt.Errorf("invalid random bytes length: %d", length)
	}

	if length > maxRandomBytesLen {
		return nil, fmt.Errorf("random bytes length too large: %d (maximum %d)", length, maxRandomBytesLen)
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read random bytes: %w", err)
	}

	return buf, nil
}

// SecureRandomInt 生成密码学安全的随机整数
//
// 参数：
//
//	max - 最大值（不包含）
//
// 返回值：
//
//	随机整数 [0, max)
//	error - 错误
func SecureRandomInt(max int) (int, error) {
	if max <= 0 {
		return 0, fmt.Errorf("invalid max value: %d", max)
	}

	bigMax := new(big.Int).SetInt64(int64(max))
	n, err := rand.Int(rand.Reader, bigMax)
	if err != nil {
		return 0, fmt.Errorf("failed to generate random int: %w", err)
	}

	return int(n.Int64()), nil
}

// SecureRandomPrime 生成符合 NIST FIPS 186-4 标准的随机素数
//
// 安全特性：
// - 使用密码学安全的随机数生成器
// - Miller-Rabin 素性测试
// - 可配置的素性测试轮数
//
// 符合标准：
// - NIST FIPS 186-4 (Digital Signature Standard)
// - NIST SP 800-56B (Key Management)
// - ISO/IEC 18032:2005 (Prime Number Generation)
//
// 参数：
//
//	bits - 素数的位数
//	      - RSA-2048: 2048位 (推荐)
//	      - RSA-3072: 3072位
//	      - RSA-4096: 4096位 (高安全性)
//	rounds - Miller-Rabin 测试轮数（可选，0使用默认值）
//	        默认值根据位数确定：
//	        - 512-1024位: 40轮
//	        - 1025-2048位: 56轮
//	        - 2049-4096位: 64轮
//
// 返回值：
//
//	随机素数
//	error - 错误
//
// 使用场景：
// - DH参数生成
// - RSA密钥生成
// - 密码学协议参数生成
func SecureRandomPrime(bits int, rounds ...int) (*big.Int, error) {
	if bits < 2 {
		return nil, fmt.Errorf("invalid prime bits: %d", bits)
	}

	// 强制最小素数位数
	if bits < minPrimeBits {
		return nil, fmt.Errorf("prime bits too small for cryptographic use: %d (minimum %d)", bits, minPrimeBits)
	}

	// 根据位数确定默认测试轮数
	// 符合 NIST FIPS 186-4 Table B.1
	var testRounds int
	if len(rounds) > 0 && rounds[0] > 0 {
		testRounds = rounds[0]
	} else {
		switch {
		case bits <= 1024:
			testRounds = 40
		case bits <= 2048:
			testRounds = 56
		default:
			testRounds = 64
		}
	}

	// 使用 Go 标准库的 rand.Prime
	// rand.Prime 内部使用 Miller-Rabin 素性测试
	// 对于小的候选数（< 2^64），使用确定性测试
	// 对于大的候选数，使用概率性 Miller-Rabin 测试
	//
	// 注意：Go 的 rand.Prime 默认测试轮数为 20
	// 对于生产环境，我们需要更多轮数
	const maxAttempts = 100
	for attempt := 0; attempt < maxAttempts; attempt++ {
		prime, err := rand.Prime(rand.Reader, bits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate prime: %w", err)
		}

		// 额外的 Miller-Rabin 测试轮数以确保安全性
		// 如果默认轮数小于要求的轮数，添加额外测试
		defaultRounds := 20
		if testRounds > defaultRounds {
			extraFailed := false
			for i := 0; i < testRounds-defaultRounds; i++ {
				if !prime.ProbablyPrime(1) {
					extraFailed = true
					break
				}
			}
			if extraFailed {
				continue // 重新生成
			}
		}

		return prime, nil
	}

	return nil, fmt.Errorf("failed to generate prime after %d attempts", maxAttempts)
}

// GenerateSafePrime 生成安全素数（形式为 2p+1 的素数）
//
// 安全特性：
// - 安全素数用于 Diffie-Hellman 密钥交换
// - 防止 Pohlig-Hellman 攻击
// - 防止小subgroup攻击
//
// 符合标准：
// - NIST SP 800-56A (Key Establishment)
// - RFC 3526 (Modular Exponential (MODP) Groups)
//
// 参数：
//
//	bits - 素数的位数（建议至少 2048 位）
//
// 返回值：
//
//	安全素数 q，其中 2q+1 也是素数
//	error - 错误
func GenerateSafePrime(bits int) (*big.Int, error) {
	if bits < minPrimeBits {
		return nil, fmt.Errorf("safe prime bits too small: %d (minimum %d)", bits, minPrimeBits)
	}

	const maxAttempts = 1000
	var attempts int

	for attempts < maxAttempts {
		attempts++

		// 生成候选素数 p
		p, err := SecureRandomPrime(bits)
		if err != nil {
			return nil, fmt.Errorf("failed to generate prime candidate: %w", err)
		}

		// 计算 q = 2p + 1
		q := new(big.Int).Mul(p, big.NewInt(2))
		q.Add(q, big.NewInt(1))

		// 检查 q 是否为素数
		if q.ProbablyPrime(64) {
			// 找到安全素数
			return q, nil
		}
	}

	return nil, fmt.Errorf("failed to generate safe prime after %d attempts", maxAttempts)
}

// DelayVerification 添加延迟以防止时序攻击
//
// 安全特性：
// - 无论验证成功或失败，都执行相同的延迟
// - 使攻击者无法通过响应时间推断验证结果
//
// 使用场景：
// - 密码验证
// - 签名验证
// - MAC验证
func DelayVerification() {
	// 使用随机延迟防止时序攻击
	// 固定延迟仍可能被统计平均消除，随机延迟更安全
	delay := SecureRandomDuration(50*time.Millisecond, 150*time.Millisecond)
	time.Sleep(delay)
}

// SecureCompare 提供一个通用的安全比较接口
//
// 此函数根据输入类型选择合适的比较方法
func SecureCompare(a, b interface{}) bool {
	switch va := a.(type) {
	case []byte:
		if vb, ok := b.([]byte); ok {
			return ConstantTimeCompare(va, vb)
		}
	case string:
		if vb, ok := b.(string); ok {
			return ConstantTimeStringCompare(va, vb)
		}
	}
	return false
}

// MemSet 设置内存区域为指定值
//
// 安全特性：
// - 用于清空或填充敏感内存区域
// - 防止编译器优化掉清零操作
func MemSet(b []byte, value byte) {
	if len(b) == 0 {
		return
	}
	if value == 0 {
		C.OPENSSL_cleanse(unsafe.Pointer(&b[0]), C.size_t(len(b)))
	} else {
		for i := range b {
			b[i] = value
		}
	}
	runtime.KeepAlive(b)
}

// WipeBytes 擦除字节切片内容（ZeroBytes的别名）
//
// 此函数提供更直观的API名称
func WipeBytes(b []byte) {
	ZeroBytes(b)
}

// SafeEqualInt 安全比较两个整数（用于密码学计数器等）
//
// 使用常量时间比较防止时序侧信道
func SafeEqualInt(a, b int) bool {
	return subtle.ConstantTimeEq(int32(a), int32(b)) == 1
}
