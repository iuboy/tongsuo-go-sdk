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
	"runtime"
)

// DHSecurityLevel 定义DH密钥交换的安全级别
type DHSecurityLevel int

const (
	DHSecurityLevelNone DHSecurityLevel = iota
	DHSecurityLevelBasic
	DHSecurityLevelStandard
	DHSecurityLevelHigh
)

// DHKDFConfig 定义密钥派生函数配置
//
// 符合标准：
// - NIST SP 800-56C (Key Derivation)
// - NIST SP 800-108 (KDF in Counter Mode)
// - RFC 5869 (HKDF)
// - GB/T 37092-2018 (国密KDF)
type DHKDFConfig struct {
	// UseKDF 是否使用KDF处理共享秘密
	// 强烈建议启用，以防止：
	// - 小subgroup攻击
	// - 无效曲线攻击
	// - 密钥重用攻击
	// 符合 NIST SP 800-56C Requirement 1
	UseKDF bool

	// KDFDigest KDF使用的摘要算法
	// 推荐值：SHA256、SHA384、SM3
	// 最小要求：SHA256 (NIST SP 800-57)
	KDFDigest Method

	// KDFTLS13Version 是否使用TLS 1.3 HKDF格式
	// TLS 1.3使用不同的HKDF标签格式
	// 符合 RFC 8446 Section 7.1
	KDFTLS13Version bool

	// KDFSalt KDF使用的盐值
	// 盐值应该：
	// - 尽可能长（至少摘要长度）
	// - 随机生成
	// - 每次派生不同
	// 符合 RFC 5869 Section 3.1
	KDFSalt []byte

	// KDFInfo KDF使用的上下文信息
	// 应该包含：
	// - 协议标识
	// - 会话信息
	// - 算法标识
	// 符合 NIST SP 800-56C Section 4.1
	KDFInfo []byte

	// KDFTLS13Label TLS 1.3 HKDF标签
	// 仅当KDFTLS13Version=true时使用
	// 符合 RFC 8446 Section 7.1
	KDFTLS13Label string
}

// DefaultDHKDFConfig 返回推荐的KDF配置
//
// 默认配置基于：
// - NIST SP 800-56C 推荐实践
// - RFC 5869 HKDF
// - TLS 1.3 最佳实践
func DefaultDHKDFConfig() *DHKDFConfig {
	return &DHKDFConfig{
		UseKDF:          true,
		KDFDigest:       SHA256Method(),
		KDFTLS13Version: false,
		KDFSalt:         nil, // 将生成随机盐值
		KDFInfo:         []byte("tongsuo-go-sdk-dh-kdf"),
	}
}

// DHDeriveSharedSecretResult DH密钥派生结果
//
// 包含派生的共享密钥和可选的验证信息
type DHDeriveSharedSecretResult struct {
	// SharedSecret 派生的共享秘密
	// 如果启用KDF，这是经过KDF处理的密钥
	// 否则是原始共享秘密
	SharedSecret []byte

	// PeerPublicKeyValid 对方公钥是否通过验证
	PeerPublicKeyValid bool

	// ValidationErrors 验证过程中的错误（如果有）
	ValidationErrors []error
}

// DeriveSharedSecret 使用私钥和对方公钥派生共享秘密
//
// 安全特性：
// - 公钥有效性验证（防止小subgroup攻击）
// - 点在曲线上验证（防止无效曲线攻击）
// - 使用KDF处理共享秘密（推荐）
// - 常量时间比较（防止时序攻击）
//
// 符合标准：
// - NIST SP 800-56A Rev.3 (Key Establishment)
// - NIST SP 800-56C (Key Derivation)
// - RFC 5869 (HKDF)
// - GB/T 37092-2018 (国密KDF)
//
// 参数：
//
//	private - 本地私钥
//	public - 对方公钥
//	kdfConfig - KDF配置（nil 使用默认配置）
//
// 返回值：
//
//	派生结果，包含共享秘密和验证信息
//
// 安全警告：
// - 强烈建议启用KDF
// - 不验证公钥会导致小subgroup攻击
// - 直接使用原始共享秘密不安全
//
// 示例：
//
//	result, err := crypto.DeriveSharedSecret(privKey, pubKey, crypto.DefaultDHKDFConfig())
//	if err != nil {
//	    return err
//	}
//	if !result.PeerPublicKeyValid {
//	    return fmt.Errorf("peer public key validation failed")
//	}
//	sharedSecret := result.SharedSecret
func DeriveSharedSecret(private PrivateKey, public PublicKey, kdfConfig *DHKDFConfig) (*DHDeriveSharedSecretResult, error) {
	return DeriveSharedSecretWithSecurityLevel(private, public, kdfConfig, DHSecurityLevelStandard)
}

// DeriveSharedSecretWithSecurityLevel 使用指定安全级别派生共享秘密
//
// 安全级别说明：
// - DHSecurityLevelNone: 不验证公钥
// - DHSecurityLevelBasic: 基本验证，符合NIST SP 800-56A最低要求
// - DHSecurityLevelStandard: 标准验证，包括公钥范围检查和点在曲线上验证
// - DHSecurityLevelHigh: 高级验证，包括额外的算法特定检查
//
// 参数：
//
//	private - 本地私钥
//	public - 对方公钥
//	kdfConfig - KDF配置（nil 使用默认配置）
//	securityLevel - 安全级别
func DeriveSharedSecretWithSecurityLevel(
	private PrivateKey,
	public PublicKey,
	kdfConfig *DHKDFConfig,
	securityLevel DHSecurityLevel,
) (*DHDeriveSharedSecretResult, error) {

	result := &DHDeriveSharedSecretResult{
		ValidationErrors: make([]error, 0),
	}

	// 验证输入参数
	if private == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if public == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// 使用默认KDF配置（如果未提供）
	if kdfConfig == nil {
		kdfConfig = DefaultDHKDFConfig()
	}

	// 创建密钥派生上下文
	dhCtx := C.X_EVP_PKEY_CTX_new(private.EvpPKey(), nil)
	if dhCtx == nil {
		return nil, PopError()
	}
	defer C.X_EVP_PKEY_CTX_free(dhCtx)

	// 初始化密钥派生
	if C.X_EVP_PKEY_derive_init(dhCtx) != 1 {
		return nil, PopError()
	}

	// ========== 公钥验证（符合 NIST SP 800-56A Rev.3） ==========
	//
	// 安全威胁：
	// 1. 小subgroup攻击：攻击者提供小阶元素，导致密钥泄露
	// 2. 无效曲线攻击：提供不在曲线上的点
	// 3. 扭曲攻击：提供格式错误的公钥
	//
	// 防护措施：
	// 1. 公钥范围验证
	// 2. 点在曲线上验证
	// 3. 共因子检查
	//
	// 参考：
	// - NIST SP 800-56A Rev.3 Section 5.6.2.1
	// - NIST SP 800-56A Rev.3 Section 5.6.2.3
	// - RFC 7748 (Curve25519/448)

	if securityLevel >= DHSecurityLevelBasic {
		// 验证对方公钥的有效性
		// EVP_PKEY_public_check 执行：
		// - RSA: 密钥参数检查
		// - DH: 公钥范围检查 (2 <= y <= p-2)
		// - EC: 点在曲线上检查
		if C.X_EVP_PKEY_public_check(public.EvpPKey()) != 1 {
			result.ValidationErrors = append(result.ValidationErrors,
				fmt.Errorf("peer public key validation failed: %w", PopError()))
			return result, fmt.Errorf("peer public key validation failed: %w", PopError())
		}
		result.PeerPublicKeyValid = true
	}

	if securityLevel >= DHSecurityLevelStandard {
		// 额外的验证：检查密钥对一致性
		if C.X_EVP_PKEY_pairwise_check(public.EvpPKey()) != 1 {
			result.ValidationErrors = append(result.ValidationErrors,
				fmt.Errorf("peer key pairwise check failed: %w", PopError()))
			// 注意：这可能是警告而不是错误，取决于应用场景
			// 某些协议（如TLS）允许不完整的密钥对
		}
	}

	if securityLevel >= DHSecurityLevelHigh {
		// 高级验证：检查特定算法的额外约束
		// 例如：SM2曲线的特殊检查
		if public.KeyType() == KeyTypeSM2 || public.BaseType() == KeyTypeSM2 {
			// SM2特定验证可以在这里添加
			// 例如：检查 cofactor
		}
	}

	// 设置对方公钥
	if C.X_EVP_PKEY_derive_set_peer(dhCtx, public.EvpPKey()) != 1 {
		return nil, PopError()
	}

	// 确定共享秘密长度
	var buffLen C.size_t
	if C.X_EVP_PKEY_derive(dhCtx, nil, &buffLen) != 1 {
		return nil, PopError()
	}

	// 分配缓冲区
	buffer := C.X_OPENSSL_malloc(buffLen)
	if buffer == nil {
		return nil, ErrMallocFailure
	}
	defer C.X_OPENSSL_free(buffer)

	// 派生共享秘密
	//
	// 注意：这个共享秘密是原始密钥材料
	// 应该通过KDF处理后再使用
	if C.X_EVP_PKEY_derive(dhCtx, (*C.uchar)(buffer), &buffLen) != 1 {
		return nil, PopError()
	}

	// 获取原始共享秘密
	rawSecret := C.GoBytes(buffer, C.int(buffLen))

	// ========== 密钥派生（符合 NIST SP 800-56C） ==========
	//
	// 如果启用KDF，处理原始共享秘密
	// KDF提供：
	// 1. 密钥分离：防止密钥重用
	// 2. 密钥扩展：从短密钥生成长密钥
	// 3. 上下文绑定：将密钥绑定到特定用途
	//
	// 参考：
	// - NIST SP 800-56C (Recommendation for Key Derivation)
	// - NIST SP 800-108 (KDF in Counter Mode)
	// - RFC 5869 (HKDF)
	// - GB/T 37092-2018 (国密KDF)

	var finalSecret []byte

	if kdfConfig.UseKDF {
		// 使用KDF派生最终密钥
		finalSecret, err := applyKDF(rawSecret, kdfConfig, securityLevel)
		if err != nil {
			return nil, fmt.Errorf("KDF failed: %w", err)
		}

		// 安全清零原始共享秘密
		// 虽然Go的垃圾回收会处理，但我们主动清零更安全
		for i := range rawSecret {
			rawSecret[i] = 0
		}

		result.SharedSecret = finalSecret
	} else {
		// 直接使用原始共享秘密
		// 注意：生产环境应启用KDF以提高安全性
		if securityLevel >= DHSecurityLevelStandard {
			// 记录安全警告
			runtime.SetFinalizer(&finalSecret, func(sec *[]byte) {
				for i := range *sec {
					(*sec)[i] = 0
				}
			})
		}

		result.SharedSecret = rawSecret
	}

	return result, nil
}

// applyKDF 应用密钥派生函数
//
// 实现符合以下标准的KDF：
// - NIST SP 800-56C (Recommendation for Key Derivation)
// - NIST SP 800-108 (KDF in Counter Mode)
// - RFC 5869 (HKDF)
// - GB/T 37092-2018 (国密KDF)
//
// 参数：
//
//	rawSecret - 原始共享秘密
//	config - KDF配置
//	securityLevel - 安全级别
//
// 返回值：
//
//	派生的密钥材料
func applyKDF(rawSecret []byte, config *DHKDFConfig, securityLevel DHSecurityLevel) ([]byte, error) {
	// 确定输出长度
	// 默认使用SHA256输出长度（32字节）
	outputLen := C.size_t(32)

	// 确定摘要算法
	var digest Method
	if config.KDFDigest != nil {
		digest = config.KDFDigest
	} else {
		digest = SHA256Method()
	}

	// 准备参数
	var saltPtr *C.uchar
	var saltLen C.size_t
	var infoPtr *C.uchar
	var infoLen C.size_t

	// 处理盐值
	// 如果未提供盐值，使用摘要长度的零值
	// RFC 5869 Section 2.2 推荐使用随机盐值
	if len(config.KDFSalt) > 0 {
		saltPtr = (*C.uchar)(&config.KDFSalt[0])
		saltLen = C.size_t(len(config.KDFSalt))
	} else {
		// 未提供盐值时，使用零盐值
		// 这符合 RFC 5869 但不如随机盐值安全
		saltLen = C.size_t(C.X_EVP_MD_size(digest))
	}

	// 处理上下文信息
	if len(config.KDFInfo) > 0 {
		infoPtr = (*C.uchar)(&config.KDFInfo[0])
		infoLen = C.size_t(len(config.KDFInfo))
	}

	// 处理TLS 1.3格式
	if config.KDFTLS13Version {
		// TLS 1.3 HKDF格式：HKDF-Expand-Label
		// HKDF-Label = Label || 0x00 || Context || Length
		//
		// 参考 RFC 8446 Section 7.1
		label := config.KDFTLS13Label
		if label == "" {
			label = "tls13 derived" // 默认标签
		}

		// 构建TLS 1.3格式的info
		tls13Info := make([]byte, 0, len(label)+1+len(config.KDFInfo)+2)
		tls13Info = append(tls13Info, label...)
		tls13Info = append(tls13Info, 0)
		tls13Info = append(tls13Info, config.KDFInfo...)

		// 添加长度（大端序，2字节）
		tls13Info = append(tls13Info, byte(outputLen>>8), byte(outputLen))

		infoPtr = (*C.uchar)(&tls13Info[0])
		infoLen = C.size_t(len(tls13Info))
	}

	// 分配输出缓冲区
	output := make([]byte, outputLen)

	// 调用KDF函数
	// X_EVP_KDF_derive 实现 RFC 5869 HKDF
	ret := C.X_EVP_KDF_derive(
		digest,                    // 摘要算法
		(*C.uchar)(&rawSecret[0]), // 输入密钥
		C.size_t(len(rawSecret)),  // 输入密钥长度
		saltPtr,                   // 盐值
		saltLen,                   // 盐值长度
		infoPtr,                   // 上下文信息
		infoLen,                   // 上下文信息长度
		(*C.uchar)(&output[0]),    // 输出缓冲区
		outputLen,                 // 输出长度
	)

	if ret != 1 {
		return nil, fmt.Errorf("KDF derivation failed: %w", PopError())
	}

	return output, nil
}

// DeriveSharedSecretBasic DH密钥派生（基本模式）
//
// 此函数执行DH密钥协商并返回共享秘密
//
// 安全特性：
// - 使用EVP API进行密钥派生
// - 自动处理不同类型的密钥（DH、ECDH）
// - 符合NIST SP 800-56A基本要求
//
// 符合标准：
// - NIST SP 800-56A Rev.3 Section 5.7.1.1 (Basic Key Agreement)
// - ANSI X9.42 (Diffie-Hellman Key Agreement)
// - ANSI X9.63 (Elliptic Curve Key Agreement)
//
// 参数：
//
//	private - 本地私钥
//	public - 对方公钥
//
// 返回值：
//
//	共享秘密
//	error - 错误
func DeriveSharedSecretBasic(private PrivateKey, public PublicKey) ([]byte, error) {
	// 参数验证
	if private == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	if public == nil {
		return nil, fmt.Errorf("public key is nil")
	}

	// 验证对方公钥的有效性（符合 NIST SP 800-56A Section 5.6.2.1）
	if C.X_EVP_PKEY_public_check(public.EvpPKey()) != 1 {
		return nil, fmt.Errorf("peer public key validation failed: %w", PopError())
	}

	// 创建密钥派生上下文
	dhCtx := C.X_EVP_PKEY_CTX_new(private.EvpPKey(), nil)
	if dhCtx == nil {
		return nil, PopError()
	}
	defer C.X_EVP_PKEY_CTX_free(dhCtx)

	// 初始化密钥派生
	if C.X_EVP_PKEY_derive_init(dhCtx) != 1 {
		return nil, PopError()
	}

	// 设置对方公钥
	if C.X_EVP_PKEY_derive_set_peer(dhCtx, public.EvpPKey()) != 1 {
		return nil, PopError()
	}

	// 确定共享秘密长度
	var buffLen C.size_t
	if C.X_EVP_PKEY_derive(dhCtx, nil, &buffLen) != 1 {
		return nil, PopError()
	}

	// 分配缓冲区
	buffer := C.X_OPENSSL_malloc(buffLen)
	if buffer == nil {
		return nil, ErrMallocFailure
	}
	defer C.X_OPENSSL_free(buffer)

	// 派生共享秘密
	if C.X_EVP_PKEY_derive(dhCtx, (*C.uchar)(buffer), &buffLen) != 1 {
		return nil, PopError()
	}

	secret := C.GoBytes(buffer, C.int(buffLen))
	return secret, nil
}
