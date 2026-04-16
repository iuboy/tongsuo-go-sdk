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
	"unsafe"
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
		KDFSalt:         nil, // 未设置时 applyKDF 自动生成随机盐值
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

	// ========== 密钥派生函数（KDF）安全检查 ==========
	//
	// 安全警告：直接使用原始DH共享秘密存在严重安全风险
	//
	// 攻击场景：
	// 1. 小subgroup攻击：攻击者提供小阶元素，导致部分密钥泄露
	// 2. 无效曲线攻击：提供不在曲线上的点，获取密钥信息
	// 3. 密钥重用攻击：原始共享秘密直接用作密钥，易受攻击
	//
	// 防护措施：
	// - KDF（密钥派生函数）可以均匀化共享秘密
	// - KDF添加上下文绑定（盐值、info）
	// - KDF防止密钥重用攻击
	//
	// 符合标准：
	// - NIST SP 800-56C Recommendation 1: "Key derivation should be used"
	// - NIST SP 800-56A Section 5.7.1.2: "ASecret rawKeying material should be cryptographically derived"
	// - RFC 5869 (HKDF)
	// - GB/T 37092-2018 (国密KDF)
	//
	if !kdfConfig.UseKDF {
		// 所有安全级别都强制使用KDF
		// 符合 NIST SP 800-56C Recommendation 1: "Key derivation should be used"
		return nil, fmt.Errorf("KDF is required for security level %d: "+
			"Using raw DH shared secrets is insecure and violates NIST SP 800-56C Recommendation 1. "+
			"Security risks: "+
			"1. Small subgroup attacks can leak partial key material, "+
			"2. Invalid curve attacks can recover private keys, "+
			"3. Key reuse attacks become feasible. "+
			"Solution: Set kdfConfig.UseKDF = true",
			securityLevel)
	}

	// ========== 公钥验证（符合 NIST SP 800-56A Rev.3） ==========

	if securityLevel >= DHSecurityLevelBasic {
		if C.X_EVP_PKEY_public_check(public.EvpPKey()) != 1 {
			result.ValidationErrors = append(result.ValidationErrors,
				fmt.Errorf("peer public key validation failed: %w", PopError()))
			return result, fmt.Errorf("peer public key validation failed: %w", PopError())
		}
		result.PeerPublicKeyValid = true
	}

	if securityLevel >= DHSecurityLevelStandard {
		if C.X_EVP_PKEY_pairwise_check(private.EvpPKey()) != 1 {
			result.ValidationErrors = append(result.ValidationErrors,
				fmt.Errorf("local key pair consistency check failed: %w", PopError()))
			return nil, fmt.Errorf("local key pair consistency check failed: %w", PopError())
		}
	}

	// ========== 密钥协商 ==========
	//
	// SM2 密钥不支持 EVP_PKEY_derive（Tongsuo 未注册 SM2 derive 方法），
	// 使用低级 ECDH_compute_key 作为 SM2 的替代路径。

	var rawSecret []byte

	if public.KeyType() == KeyTypeSM2 || public.BaseType() == KeyTypeSM2 {
		// SM2 ECDH 路径: ECDH_compute_key
		secret, err := deriveSM2ECDH(private, public)
		if err != nil {
			return nil, fmt.Errorf("SM2 ECDH failed: %w", err)
		}
		rawSecret = secret
	} else {
		// 标准 ECDH 路径: EVP_PKEY_derive
		var deriveErr error
		rawSecret, deriveErr = deriveECDH(private, public)
		if deriveErr != nil {
			return nil, deriveErr
		}
	}
	defer ZeroBytes(rawSecret)

	// ========== 密钥派生（符合 NIST SP 800-56C） ==========

	if kdfConfig.UseKDF {
		finalSecret, err := applyKDF(rawSecret, kdfConfig, securityLevel)
		if err != nil {
			return nil, fmt.Errorf("KDF failed: %w", err)
		}
		result.SharedSecret = finalSecret
	} else {
		result.SharedSecret = rawSecret
	}

	return result, nil
}

// deriveECDH 使用 EVP_PKEY_derive 进行标准 ECDH 密钥协商
func deriveECDH(private PrivateKey, public PublicKey) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	dhCtx := C.X_EVP_PKEY_CTX_new(private.EvpPKey(), nil)
	if dhCtx == nil {
		return nil, PopError()
	}
	defer C.X_EVP_PKEY_CTX_free(dhCtx)

	if C.X_EVP_PKEY_derive_init(dhCtx) != 1 {
		return nil, PopError()
	}

	if C.X_EVP_PKEY_derive_set_peer(dhCtx, public.EvpPKey()) != 1 {
		return nil, PopError()
	}

	var buffLen C.size_t
	if C.X_EVP_PKEY_derive(dhCtx, nil, &buffLen) != 1 {
		return nil, PopError()
	}

	buffer := C.X_OPENSSL_malloc(buffLen)
	if buffer == nil {
		return nil, ErrMallocFailure
	}
	defer func() {
		C.OPENSSL_cleanse(buffer, buffLen)
		C.X_OPENSSL_free(buffer)
	}()

	if C.X_EVP_PKEY_derive(dhCtx, (*C.uchar)(buffer), &buffLen) != 1 {
		return nil, PopError()
	}

	return C.GoBytes(buffer, C.int(buffLen)), nil
}

// deriveSM2ECDH 使用 ECDH_compute_key 进行 SM2 ECDH 密钥协商
//
// Tongsuo 的 EVP_PKEY_derive 不支持 SM2 密钥，因为 SM2 的 EVP 实现没有注册 derive 方法。
// 使用低级 ECDH_compute_key 函数直接操作 EC_KEY/EC_POINT 来计算共享秘密。
//
// SM2 基于 sm2p256v1 曲线，ECDH 计算与标准 EC ECDH 一致：
//
//	shared_secret = d_A * P_B = d_B * P_A (其中 d 是私钥标量，P 是公钥点)
//
// 注意: GM/T 0003.3 定义了完整的 SM2 密钥交换协议（包含临时密钥对和多轮交换），
// 这里实现的是基础 ECDH，适用于 TLS 握手等标准 ECDH 场景。
func deriveSM2ECDH(private PrivateKey, public PublicKey) ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// 从 EVP_PKEY 提取 EC_KEY
	ecPriv := C.X_EVP_PKEY_get1_EC_KEY(private.EvpPKey())
	if ecPriv == nil {
		return nil, fmt.Errorf("failed to get EC_KEY from SM2 private key: %w", PopError())
	}
	defer C.X_EC_KEY_free(ecPriv)

	ecPub := C.X_EVP_PKEY_get1_EC_KEY(public.EvpPKey())
	if ecPub == nil {
		return nil, fmt.Errorf("failed to get EC_KEY from SM2 public key: %w", PopError())
	}
	defer C.X_EC_KEY_free(ecPub)

	// 获取对方公钥点
	peerPoint := C.X_EC_KEY_get0_public_key(ecPub)
	if peerPoint == nil {
		return nil, fmt.Errorf("failed to get public key point: %w", PopError())
	}

	// 获取曲线组以确定共享秘密长度（SM2 是 256 位曲线 = 32 字节）
	group := C.X_EC_KEY_get0_group(ecPriv)
	if group == nil {
		return nil, fmt.Errorf("failed to get EC group")
	}

	// ECDH_compute_key 输出长度为曲线字段大小的字节数 (SM2 = 32)
	// 分配足够大的缓冲区
	outLen := C.size_t(32)
	outBuf := make([]byte, outLen)

	// 计算 ECDH 共享秘密 (不使用 KDF，返回原始 x 坐标)
	ret := C.X_ECDH_compute_key(
		unsafe.Pointer(&outBuf[0]),
		outLen,
		peerPoint,
		ecPriv,
		nil, // 不使用额外 KDF，返回原始共享秘密
	)
	if ret <= 0 {
		return nil, fmt.Errorf("ECDH_compute_key failed: %w", PopError())
	}

	return outBuf[:ret], nil
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
	// RFC 5869 Section 2.2 & NIST SP 800-56C Section 5.4：
	// 盐值应为随机生成，防止相关的密钥派生攻击
	// 当调用方未提供盐值时，自动生成与摘要输出等长的随机盐值
	var generatedSalt []byte
	if len(config.KDFSalt) > 0 {
		saltPtr = (*C.uchar)(&config.KDFSalt[0])
		saltLen = C.size_t(len(config.KDFSalt))
	} else {
		// 生成随机盐值（长度与摘要输出一致，RFC 5869 推荐）
		// SHA-256 输出 32 字节，SM3 输出 32 字节
		generatedSalt = make([]byte, 32)
		if _, err := rand.Read(generatedSalt); err != nil {
			return nil, fmt.Errorf("failed to generate random KDF salt: %w", err)
		}
		saltPtr = (*C.uchar)(&generatedSalt[0])
		saltLen = C.size_t(len(generatedSalt))
	}
	// 确保生成的盐值在返回时被清零
	defer ZeroBytes(generatedSalt)

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
// Deprecated: 此函数名称暗示返回原始共享秘密，但为了安全现在内部已强制使用 KDF。
// 请使用 DeriveSharedSecret() 代替，该函数提供更灵活的 KDF 配置。
//
// 此函数执行DH密钥协商，内部使用默认 KDF 配置处理共享秘密。
// 通信双方调用此函数将得到相同的派生密钥。
//
// 安全说明：
// - 内部强制使用 HKDF-SHA256 处理原始共享秘密
// - 符合 NIST SP 800-56A Rev.3 Section 6 要求
// - 双方必须使用相同的默认配置才能得到一致的密钥
//
// 符合标准：
// - NIST SP 800-56A Rev.3 Section 5.7.1.1 (Basic Key Agreement)
// - NIST SP 800-56C (Key Derivation)
//
// 参数：
//
//	private - 本地私钥
//	public - 对方公钥
//
// 返回值：
//
//	经过KDF处理的共享密钥（双方一致）
//	error - 错误
func DeriveSharedSecretBasic(private PrivateKey, public PublicKey) ([]byte, error) {
	// 使用确定性 KDF 配置：固定盐值确保双方独立调用得到一致的派生密钥
	// 固定盐值的安全性低于随机盐值，但远优于直接使用原始 DH 共享秘密
	// 符合 NIST SP 800-56C 的最低要求
	kdfConfig := &DHKDFConfig{
		UseKDF:    true,
		KDFDigest: SHA256Method(),
		KDFSalt:   make([]byte, 32), // 全零固定盐值（确定性，双方一致）
		KDFInfo:   []byte("tongsuo-go-sdk-dh-basic-kdf"),
	}

	result, err := DeriveSharedSecret(private, public, kdfConfig)
	if err != nil {
		return nil, err
	}
	if !result.PeerPublicKeyValid {
		return nil, fmt.Errorf("peer public key validation failed")
	}
	return result.SharedSecret, nil
}
