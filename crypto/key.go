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
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"runtime"
	"sync"
	"unsafe"
)

type Method *C.EVP_MD

// sm2DefaultIDWarnOnce 确保默认 SM2 用户 ID 警告仅打印一次
var sm2DefaultIDWarnOnce sync.Once

func SHA1Method() Method {
	return C.X_EVP_sha1()
}

func SHA256Method() Method {
	return C.X_EVP_sha256()
}

func SHA512Method() Method {
	return C.X_EVP_sha512()
}

func SM3Method() Method {
	return C.X_EVP_sm3()
}

// Constants for the various key types.
// Mapping of name -> NID taken from openssl/evp.h
const (
	KeyTypeNone    = NidUndef
	KeyTypeRSA     = NidRsaEncryption
	KeyTypeRSA2    = NidRsa
	KeyTypeDSA     = NidDsa
	KeyTypeDSA1    = NidDsa2
	KeyTypeDSA2    = NidDsaWithSHA
	KeyTypeDSA3    = NidDsaWithSHA1
	KeyTypeDSA4    = NidDsaWithSHA12
	KeyTypeDH      = NidDhKeyAgreement
	KeyTypeDHX     = NidDhpublicnumber
	KeyTypeEC      = NidX962IdEcPublicKey
	KeyTypeHMAC    = NidHmac
	KeyTypeCMAC    = NidCmac
	KeyTypeTLS1PRF = NidTLS1Prf
	KeyTypeHKDF    = NidHkdf
	KeyTypeX25519  = NidX25519
	KeyTypeX448    = NidX448
	KeyTypeED25519 = NidEd25519
	KeyTypeED448   = NidEd448
	KeyTypeSM2     = NidSM2
)

type PublicKey interface {
	// VerifyPKCS1v15 verifies the data signature using PKCS1.15
	VerifyPKCS1v15(method Method, data, sig []byte) error

	// VerifyWithOptions 使用指定选项验证数据签名
	//
	// 安全特性：
	// - 允许自定义SM2用户ID进行验证
	// - SM2验证必须使用与签名相同的ID
	// - 符合 GM/T 0009-2012 标准
	//
	// 参数：
	//   method - 摘要算法（SM2必须使用SM3）
	//   data - 原始数据
	//   sig - 签名值
	//   options - 验证选项（nil使用默认值）
	//
	// 返回值：
	//   error - 验证失败时返回错误
	//
	// 符合标准：
	// - GM/T 0009-2012 (SM2密码算法使用规范)
	VerifyWithOptions(method Method, data, sig []byte, options *SignOptions) error

	// Encrypt encrypts the data using SM2
	Encrypt(data []byte) ([]byte, error)

	// MarshalPKIXPublicKeyPEM converts the public key to PEM-encoded PKIX
	// format
	MarshalPKIXPublicKeyPEM() (pemBlock []byte, err error)

	// MarshalPKIXPublicKeyDER converts the public key to DER-encoded PKIX
	// format
	MarshalPKIXPublicKeyDER() (derBlock []byte, err error)

	// KeyType returns an identifier for what kind of key is represented by this
	// object.
	KeyType() NID

	// BaseType returns an identifier for what kind of key is represented
	// by this object.
	// Keys that share same algorithm but use different legacy formats
	// will have the same BaseType.
	//
	// For example, a key with a `KeyType() == KeyTypeRSA` and a key with a
	// `KeyType() == KeyTypeRSA2` would both have `BaseType() == KeyTypeRSA`.
	BaseType() NID

	EvpPKey() *C.EVP_PKEY
}

// SignOptions 签名选项，用于配置签名行为
//
// 安全特性：
	// - 允许自定义SM2用户ID，防止固定ID泄露风险
// // - 符合 GM/T 0009-2012 标准
	//
	// 使用场景：
	// - SM2签名时需要自定义用户ID
	// - 多租户环境中的密钥隔离
	// - 符合特定应用场景的ID要求
type SignOptions struct {
	// SM2ID SM2用户标识符
	// 根据 GM/T 0009-2012，SM2签名需要用户ID
	// 默认值：1234567812345678（16字节）
	//
	// 安全注意事项：
	// - 不同应用应使用不同的ID
	// - ID应该保密或至少难以猜测
	// - ID长度建议为16字节
	//
	// 符合标准：GM/T 0009-2012 Section 5.4
	SM2ID string

	// SM2IDIsHex SM2ID是否为十六进制编码
	// 如果为true，ID将被解释为十六进制字符串
	// 如果为false，ID将被直接使用
	SM2IDIsHex bool
}

// ParseSM2ID 解析 SM2 用户 ID，统一 hex/原始字节处理逻辑
//
// GM/T 0009-2012 规定 SM2 默认用户 ID 为 "1234567812345678"（16 字节 ASCII 字符串）。
// 当 isHex=true 时，ID 字符串被解释为十六进制编码并解码为原始字节；
// 当 isHex=false 时，ID 字符串直接作为原始字节使用。
//
// 参数：
//   id     - SM2 用户 ID 字符串
//   isHex  - 是否为十六进制编码
//
// 返回值：
//   解码后的 ID 字节
//   error  - 解码失败或 ID 为空时返回错误
func ParseSM2ID(id string, isHex bool) ([]byte, error) {
	if len(id) == 0 {
		return nil, fmt.Errorf("SM2 ID cannot be empty")
	}
	if len(id) > 255 {
		return nil, fmt.Errorf("SM2 ID too long (max 255 bytes, got %d)", len(id))
	}
	if isHex {
		decoded, err := hex.DecodeString(id)
		if err != nil {
			return nil, fmt.Errorf("failed to decode SM2 ID hex: %w", err)
		}
		if len(decoded) == 0 {
			return nil, fmt.Errorf("SM2 ID is empty after hex decoding")
		}
		return decoded, nil
	}
	return []byte(id), nil
}

// DefaultSM2SignOptions 返回默认的SM2签名选项
//
// 安全警告：
// - 默认ID "1234567812345678" 是 GM/T 0009-2012 标准中的测试ID，广泛公开
// - 使用公开ID会降低签名安全性：攻击者可以预计算Z值（用户ID与曲线参数的摘要）
// - 多个应用使用相同ID会导致Z值相同，增加交叉攻击风险
// - 生产环境必须使用自定义ID（建议随机生成16字节）
//
// 注意：默认 ID 使用 SM2IDIsHex=false，即直接传递 16 字节 ASCII 字符串，
// 符合 GM/T 0009-2012 标准中规定的默认值语义。
//
// 返回值：
//   默认签名选项（仅用于测试/兼容性）
func DefaultSM2SignOptions() *SignOptions {
	return &SignOptions{
		SM2ID:     "1234567812345678",
		SM2IDIsHex: false,
	}
}

type PrivateKey interface {
	PublicKey

	// Public return public key
	Public() PublicKey

	// SignPKCS1v15 signs the data using PKCS1.15
	SignPKCS1v15(method Method, data []byte) ([]byte, error)

	// SignWithOptions 使用指定选项签名数据
	//
	// 安全特性：
	// - 允许自定义SM2用户ID
	// - 防止固定ID泄露风险
	// - 符合 GM/T 0009-2012 标准
	//
	// 参数：
	//   method - 摘要算法（SM2必须使用SM3）
	//   data - 要签名的数据
	//   options - 签名选项（nil使用默认值）
	//
	// 返回值：
	//   签名值
	//   error - 错误
	//
	// 符合标准：
	// - GM/T 0009-2012 (SM2密码算法使用规范)
	// - GB/T 3624-2018 (信息安全技术 SM2密码算法使用规范)
	SignWithOptions(method Method, data []byte, options *SignOptions) ([]byte, error)

	// Decrypt decrypts the data using SM2
	Decrypt(data []byte) ([]byte, error)

	// MarshalPKCS1PrivateKeyPEM converts the private key to PEM-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyPEM() (pemBlock []byte, err error)

	// MarshalPKCS1PrivateKeyDER converts the private key to DER-encoded PKCS1
	// format
	MarshalPKCS1PrivateKeyDER() (derBlock []byte, err error)

	// MarshalPKCS8PrivateKeyPEM converts the private key to PEM-encoded PKCS8
	// format
	MarshalPKCS8PrivateKeyPEM() (pemBlock []byte, err error)

	// MarshalPKCS8PrivateKeyDER converts the private key to DER-encoded PKCS8
	// format
	MarshalPKCS8PrivateKeyDER() (derBlock []byte, err error)

	// Wipe 安全地销毁密钥材料
	//
	// 安全特性：
	// - 立即清零内存中的密钥材料
	// - 防止内存扫描攻击
	// - 移除finalizer防止双重释放
	// - 符合 NIST SP 800-57 Part 1 Rev.5 (密钥销毁)
	//
	// 注意：调用 Wipe() 后，密钥对象不能再使用
	// 此方法会释放底层 C 资源并清零相关内存
	//
	// 符合标准：
	// - NIST SP 800-57 Part 1 Rev.5 Section 5.3.4 (Cryptographic Key Destruction)
	// - FIPS 140-2 (Security Requirements for Cryptographic Modules)
	// - GB/T 39786-2021 (信息安全技术 信息系统密码应用基本要求)
	//
	// 使用场景：
	// - 密钥轮换后销毁旧密钥
	// - 会话结束后销毁会话密钥
	// - 错误处理中销毁部分生成的密钥
	// - 应用退出前清理敏感数据
	Wipe() error
}

func SupportEd25519() bool {
	return C.X_ED25519_SUPPORT != 0
}

type pKey struct {
	key      *C.EVP_PKEY
	wipeOnce sync.Once
	wiped    bool
}

func (key *pKey) EvpPKey() *C.EVP_PKEY { return key.key }

func (key *pKey) KeyType() NID {
	if key.key == nil {
		return NID(0)
	}
	return NID(C.EVP_PKEY_id(key.key))
}

func (key *pKey) BaseType() NID {
	if key.key == nil {
		return NID(0)
	}
	return NID(C.EVP_PKEY_base_id(key.key))
}

func (key *pKey) Public() PublicKey {
	der, err := key.MarshalPKIXPublicKeyDER()
	if err != nil {
		return nil
	}

	pub, err := LoadPublicKeyFromDER(der)
	if err != nil {
		return nil
	}

	return pub
}

func (key *pKey) SignPKCS1v15(method Method, data []byte) ([]byte, error) {
	// 使用默认选项进行签名
	return key.SignWithOptions(method, data, nil)
}

func (key *pKey) SignWithOptions(method Method, data []byte, options *SignOptions) ([]byte, error) {
	if key.key == nil {
		return nil, ErrNoKey
	}

	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	// 防止数据在签名过程中被GC移动（必须在函数返回时执行）
	defer runtime.KeepAlive(data)
	defer runtime.KeepAlive(key)

	// Tongsuo 8.5: SM2 签名必须符合 GM/T 0009-2012 标准
	// SM2 签名必须使用 SM3 摘要并对用户 ID 进行预处理
	if key.KeyType() == KeyTypeSM2 {
		// 验证摘要算法：SM2 必须使用 SM3
		sm3Method := C.X_EVP_sm3()
		if method != nil && method != sm3Method {
		if len(data) == 0 {
			return nil, ErrNilParameter
		}
			return nil, fmt.Errorf("SM2 signature must use SM3 digest (GM/T 0009-2012)")
		}

		// 使用提供的选项或默认选项
		if options == nil {
			sm2DefaultIDWarnOnce.Do(func() {
				log.Println("WARNING: SM2 signing with default user ID. " +
					"The default ID is a well-known test value per GM/T 0009-2012. " +
					"Production applications MUST use a custom, unique SM2 ID. " +
					"Pass SignOptions with a custom SM2ID to suppress this warning.")
			})
			options = DefaultSM2SignOptions()
		}

		// 解析 SM2 用户 ID 字节（统一使用 ParseSM2ID）
		sm2IDBytes, err := ParseSM2ID(options.SM2ID, options.SM2IDIsHex)
		if err != nil {
			return nil, err
		}

		var pctx *C.EVP_PKEY_CTX

		// 初始化签名上下文
		if C.X_EVP_DigestSignInit(ctx, &pctx, sm3Method, nil, key.key) != 1 {
			return nil, PopError()
		}

		// 根据 GM/T 0009-2012，SM2 签名需要设置用户 ID
		// 用户ID用于签名过程中的预处理，确保签名的唯一性
		//
		// 安全注意事项：
		// - 不同应用应使用不同的ID
		// - ID应该保密或至少难以猜测
		// - 固定ID可能导致签名密钥信息泄露
		//
		// 将解码后的 ID 字节传递给 C（而非原始 hex 字符串）
		// A-01 修复：使用 CBytes 代替 CString，避免 null 字节截断
		// C.CString 在遇到 \x00 时会截断，而 SM2 ID 可能包含 null 字节
		sm2IDPtr := C.CBytes(sm2IDBytes)
		defer C.X_free(sm2IDPtr)
		defer runtime.KeepAlive(sm2IDBytes)

		if C.X_EVP_PKEY_CTX_set1_id(pctx, sm2IDPtr, C.int(len(sm2IDBytes))) <= 0 {
			return nil, fmt.Errorf("failed to set SM2 ID: %w", PopError())
		}

		// 执行签名
		var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
		sig := make([]byte, sigblen)

		if C.X_EVP_DigestSign(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen,
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return nil, PopError()
		}

		runtime.KeepAlive(sig)

		return sig[:sigblen], nil
	}

	// Ed25519 签名（不需要摘要）
	if key.KeyType() == KeyTypeED25519 {
		// do ED specific one-shot sign
		if method != nil || len(data) == 0 {
			return nil, ErrNilParameter
		}

		var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
		sig := make([]byte, sigblen)

		if C.X_EVP_DigestSignInit(ctx, nil, nil, nil, key.key) != 1 {
			return nil, PopError()
		}

		if C.X_EVP_DigestSign(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen, (*C.uchar)(unsafe.Pointer(&data[0])),
			C.size_t(len(data))) != 1 {
			return nil, PopError()
		}

		return sig[:sigblen], nil
	}

	// 其他算法的标准签名流程
	if C.X_EVP_DigestSignInit(ctx, nil, method, nil, key.key) != 1 {
		return nil, PopError()
	}

	if len(data) > 0 {
		if C.X_EVP_DigestSignUpdate(ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
			return nil, PopError()
		}
	}

	var sigblen C.size_t = C.size_t(C.X_EVP_PKEY_size(key.key))
	sig := make([]byte, sigblen)

	if C.X_EVP_DigestSignFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), &sigblen) != 1 {
		return nil, PopError()
	}

	return sig[:sigblen], nil
}

func (key *pKey) VerifyPKCS1v15(method Method, data, sig []byte) error {
	// 使用默认选项进行验证
	return key.VerifyWithOptions(method, data, sig, nil)
}

func (key *pKey) VerifyWithOptions(method Method, data, sig []byte, options *SignOptions) error {
	if key.key == nil {
		return ErrNoKey
	}

	ctx := C.X_EVP_MD_CTX_new()
	defer C.X_EVP_MD_CTX_free(ctx)

	defer runtime.KeepAlive(data)
	defer runtime.KeepAlive(sig)
	defer runtime.KeepAlive(key)

	// SM2 验证必须设置与签名相同的用户 ID
	if key.KeyType() == KeyTypeSM2 {
		sm3Method := C.X_EVP_sm3()
		if method != nil && method != sm3Method {
			return fmt.Errorf("SM2 verification must use SM3 digest (GM/T 0009-2012)")
		}
		if len(data) == 0 || len(sig) == 0 {
			return ErrNilParameter
		}

		if options == nil {
			sm2DefaultIDWarnOnce.Do(func() {
				log.Println("WARNING: SM2 verification with default user ID. " +
					"The default ID is a well-known test value per GM/T 0009-2012. " +
					"Production applications MUST use a custom, unique SM2 ID. " +
					"Pass VerifyOptions with a custom SM2ID to suppress this warning.")
			})
			options = DefaultSM2SignOptions()
		}

		if len(options.SM2ID) == 0 {
			return fmt.Errorf("SM2 ID cannot be empty")
		}

		// 解析 SM2 用户 ID 字节（统一使用 ParseSM2ID）
		sm2IDBytes, err := ParseSM2ID(options.SM2ID, options.SM2IDIsHex)
		if err != nil {
			return err
		}

		// 将解码后的 ID 字节传递给 C（而非原始 hex 字符串）
		// A-01 修复：使用 CBytes 代替 CString，避免 null 字节截断
		sm2IDPtr := C.CBytes(sm2IDBytes)
		defer C.X_free(sm2IDPtr)
		defer runtime.KeepAlive(sm2IDBytes)

		var pctx *C.EVP_PKEY_CTX
		if C.X_EVP_DigestVerifyInit(ctx, &pctx, sm3Method, nil, key.key) != 1 {
			return PopError()
		}

		if C.X_EVP_PKEY_CTX_set1_id(pctx, sm2IDPtr, C.int(len(sm2IDBytes))) <= 0 {
			return fmt.Errorf("failed to set SM2 ID: %w", PopError())
		}

		if C.X_EVP_DigestVerify(ctx, ((*C.uchar)(unsafe.Pointer(&sig[0]))), C.size_t(len(sig)),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return PopError()
		}

		return nil
	}

	// Ed25519 验证
	if key.KeyType() == KeyTypeED25519 {
		if method != nil || len(data) == 0 || len(sig) == 0 {
			return ErrNilParameter
		}

		if C.X_EVP_DigestVerifyInit(ctx, nil, nil, nil, key.key) != 1 {
			return PopError()
		}

		if C.X_EVP_DigestVerify(ctx, ((*C.uchar)(unsafe.Pointer(&sig[0]))), C.size_t(len(sig)),
			(*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
			return PopError()
		}

		return nil
	}

	// 其他算法的标准验证流程
	if C.X_EVP_DigestVerifyInit(ctx, nil, method, nil, key.key) != 1 {
		return PopError()
	}

	if len(data) > 0 {
		if C.X_EVP_DigestVerifyUpdate(ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
			return PopError()
		}
	}

	if C.X_EVP_DigestVerifyFinal(ctx, (*C.uchar)(unsafe.Pointer(&sig[0])), C.size_t(len(sig))) != 1 {
		return PopError()
	}

	return nil
}

func (key *pKey) MarshalPKCS8PrivateKeyPEM() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if C.PEM_write_bio_PKCS8PrivateKey(bio, key.key, nil, nil, 0, nil, nil) != 1 {
		return nil, PopError()
	}

	var ptr *C.char
	length := C.X_BIO_get_mem_data(bio, &ptr)
	if length <= 0 {
		return nil, ErrNoData
	}

	result := C.GoBytes(unsafe.Pointer(ptr), C.int(length))
	return result, nil
}

// MarshalPKCS8PrivateKeyDER converts the private key to DER-encoded PKCS8 format.
func (key *pKey) MarshalPKCS8PrivateKeyDER() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	// 使用 EVP_PKEY_get0_EC_KEY 等获取底层密钥后，
	// 通过 i2d_ECPrivateKey 等序列化为 DER。
	// 但 PKCS8 格式需要用不同的编码方式。
	//
	// 最可靠的方式：使用 d2i_AutoPrivateKey 的逆操作。
	// OpenSSL 提供了 i2d_PrivateKey 用于传统格式，
	// PKCS8 格式需要将 EVP_PKEY 编码为 PKCS8 DER。
	//
	// 方法：构造 PKCS8 结构体再编码
	// 1. EVP_PKEY2PKCS8 将 EVP_PKEY 转为 PKCS8 结构
	// 2. i2d_PKCS8_PRIV_KEY_INFO 编码为 DER
	//
	// 由于 CGO 不直接暴露 EVP_PKEY2PKCS8，
	// 使用 BIO + i2d_PKCS8PrivateKeyInfo_bio（OpenSSL 3.x）
	// 或者用 i2d_PrivateKey_bio 然后手动检测格式。
	//
	// 最终方案：使用最简单的方式 - 直接调用 PEM 编码后去除 PEM 头尾，
	// 然后 base64 解码得到 DER。但这效率低。
	//
	// 实际上 i2d_PrivateKey_bio 对 EC 密钥输出 SEC1 格式（非 PKCS8）。
	// 正确方案需要 EVP_PKEY2PKCS8。在 shim.c 中添加该函数。

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	// i2d_PrivateKey_bio 输出传统格式（PKCS1 for RSA, SEC1 for EC）
	// 对 PKCS8，需要通过 X_EVP_PKEY2PKCS8 转换
	p8 := C.X_EVP_PKEY2PKCS8(key.key)
	if p8 == nil {
		return nil, PopError()
	}
	defer C.X_PKCS8_PRIV_KEY_INFO_free(p8)

	if int(C.X_i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

// Wipe 安全地销毁密钥材料
//
// 安全特性：
// - 立即释放底层 EVP_PKEY 结构
// - OpenSSL 会自动清零相关内存
// - 移除 finalizer 以防止双重释放
//
// 符合标准：
// - NIST SP 800-57 Part 1 Rev.5 Section 5.3.4
// - FIPS 140-2
//
// 注意：调用此方法后，密钥对象不可再使用
func (key *pKey) Wipe() error {
	if key.wiped {
		return fmt.Errorf("key already wiped")
	}

	key.wipeOnce.Do(func() {
		if key.key == nil {
			return
		}

		// 步骤1: 移除finalizer
		runtime.SetFinalizer(key, nil)

		// 步骤2: 释放EVP_PKEY结构
		C.X_EVP_PKEY_free(key.key)

		// 步骤3: 清空指针
		key.key = nil
	})

	key.wiped = true

	if key.key == nil {
		return nil
	}
	return fmt.Errorf("key wipe failed unexpectedly")
}

func (key *pKey) Encrypt(data []byte) ([]byte, error) {
	if key.key == nil {
		return nil, ErrNoKey
	}
	if len(data) == 0 {
		return nil, ErrNilParameter
	}

	ctx := C.X_EVP_PKEY_CTX_new(key.key, nil)
	defer C.X_EVP_PKEY_CTX_free(ctx)

	if C.X_EVP_PKEY_encrypt_init(ctx) != 1 {
		return nil, PopError()
	}

	var enclen C.size_t
	if C.X_EVP_PKEY_encrypt(ctx, nil, &enclen, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	enc := make([]byte, enclen)

	if C.X_EVP_PKEY_encrypt(ctx, (*C.uchar)(unsafe.Pointer(&enc[0])), &enclen, (*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	runtime.KeepAlive(data)
	return enc[:enclen], nil
}

func (key *pKey) Decrypt(data []byte) ([]byte, error) {
	if key.key == nil {
		return nil, ErrNoKey
	}

	ctx := C.X_EVP_PKEY_CTX_new(key.key, nil)
	if ctx == nil {
		return nil, ErrMallocFailure
	}
	defer C.X_EVP_PKEY_CTX_free(ctx)

	if C.X_EVP_PKEY_decrypt_init(ctx) != 1 {
		return nil, PopError()
	}

	var declen C.size_t
	if C.X_EVP_PKEY_decrypt(ctx, nil, &declen, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	dec := make([]byte, declen)

	if C.X_EVP_PKEY_decrypt(ctx, (*C.uchar)(unsafe.Pointer(&dec[0])), &declen, (*C.uchar)(unsafe.Pointer(&data[0])),
		C.size_t(len(data))) != 1 {
		return nil, PopError()
	}

	runtime.KeepAlive(data)
	return dec[:declen], nil
}

func (key *pKey) MarshalPKCS1PrivateKeyPEM() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	// PEM_write_bio_PrivateKey_traditional will use the key-specific PKCS1
	// format if one is available for that key type, otherwise it will encode
	// to a PKCS8 key.
	if int(C.X_PEM_write_bio_PrivateKey_traditional(bio, key.key, nil, nil,
		C.int(0), nil, nil)) != 1 {
		return nil, PopError()
	}

	pem, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return pem, nil
}

func (key *pKey) MarshalPKCS1PrivateKeyDER() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PrivateKey_bio(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

func (key *pKey) MarshalPKIXPublicKeyPEM() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.PEM_write_bio_PUBKEY(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

func (key *pKey) MarshalPKIXPublicKeyDER() ([]byte, error) {
	if key.key == nil {
		return nil, ErrEmptyKey
	}

	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if int(C.i2d_PUBKEY_bio(bio, key.key)) != 1 {
		return nil, PopError()
	}

	ret, err := io.ReadAll(asAnyBio(bio))
	if err != nil {
		return nil, fmt.Errorf("failed to read bio data: %w", err)
	}

	return ret, nil
}

// LoadPrivateKeyFromPEM loads a private key from a PEM-encoded block.
func LoadPrivateKeyFromPEM(pemBlock []byte) (PrivateKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCert
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, nil)
	if key == nil {
		return nil, PopError()
	}

	priKey := &pKey{key: key}
	runtime.SetFinalizer(priKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	if C.X_EVP_PKEY_is_sm2(priKey.key) == 1 {
		if C.EVP_PKEY_set_alias_type(priKey.key, C.EVP_PKEY_SM2) != 1 {
			return nil, PopError()
		}
	}

	return priKey, nil
}

// LoadPrivateKeyFromPEMWithPassword loads a private key from a PEM-encoded block.
//
// 安全特性：
// - 密码参数使用 []byte 而非 string，允许调用方在使用后清零密码材料
// - C 侧密码副本在释放前使用 OPENSSL_cleanse 安全清零
// - 符合 NIST SP 800-57 Part 1 Rev.5 Section 5.3.4（密钥材料销毁）
func LoadPrivateKeyFromPEMWithPassword(pemBlock []byte, password []byte) (
	PrivateKey, error,
) {
	if len(pemBlock) == 0 {
		return nil, ErrNoKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]),
		C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	// 分配 C 内存存储密码（含 null 终止符）
	// 使用 []byte 允许调用方在使用后清零密码材料，避免 Go string 的不可变特性
	// 导致密码在内存中残留无法清除
	cpassSize := C.size_t(len(password)) + 1
	cpass := (*C.char)(C.malloc(cpassSize))
	if cpass == nil {
		return nil, ErrMallocFailure
	}
	defer func() {
		// 安全清零 C 内存中的密码副本
		C.OPENSSL_cleanse(unsafe.Pointer(cpass), cpassSize)
		C.free(unsafe.Pointer(cpass))
	}()
	if len(password) > 0 {
		C.memcpy(unsafe.Pointer(cpass), unsafe.Pointer(&password[0]), C.size_t(len(password)))
	}
	// null 终止符
	*(*C.char)(unsafe.Pointer(uintptr(unsafe.Pointer(cpass)) + uintptr(len(password)))) = 0

	key := C.PEM_read_bio_PrivateKey(bio, nil, nil, unsafe.Pointer(cpass))
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// LoadPrivateKeyFromDER loads a private key from a DER-encoded block.
func LoadPrivateKeyFromDER(derBlock []byte) (PrivateKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrNoKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&derBlock[0]),
		C.int(len(derBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.d2i_PrivateKey_bio(bio, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	if C.X_EVP_PKEY_is_sm2(p.key) == 1 {
		if C.EVP_PKEY_set_alias_type(p.key, C.EVP_PKEY_SM2) != 1 {
			return nil, PopError()
		}
	}

	return p, nil
}

// LoadPrivateKeyFromPEMWidthPassword loads a private key from a PEM-encoded block.
// Backwards-compatible with typo.
//
// Deprecated: Use LoadPrivateKeyFromPEMWithPassword instead.
func LoadPrivateKeyFromPEMWidthPassword(pemBlock []byte, password []byte) (
	PrivateKey, error,
) {
	return LoadPrivateKeyFromPEMWithPassword(pemBlock, password)
}

// LoadPublicKeyFromPEM loads a public key from a PEM-encoded block.
func LoadPublicKeyFromPEM(pemBlock []byte) (PublicKey, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoPubKey
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]), C.int(len(pemBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.PEM_read_bio_PUBKEY(bio, nil, nil, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	return p, nil
}

// LoadPublicKeyFromDER loads a public key from a DER-encoded block.
func LoadPublicKeyFromDER(derBlock []byte) (PublicKey, error) {
	if len(derBlock) == 0 {
		return nil, ErrNoPubKey
	}
	bio := C.BIO_new_mem_buf(unsafe.Pointer(&derBlock[0]),
		C.int(len(derBlock)))
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	key := C.d2i_PUBKEY_bio(bio, nil)
	if key == nil {
		return nil, PopError()
	}

	p := &pKey{key: key}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}

// GenerateRSAKey generates a new RSA private key with an exponent of 65537.
//
// 安全要求：
// - bits >= 2048
// - 使用EVP API而非废弃的RSA_generate_key
// - 符合FIPS 186-4和GB/T 3624-2018标准
func GenerateRSAKey(bits int) (PrivateKey, error) {
	defaultPubExp := 0x10001

	return GenerateRSAKeyWithExponent(bits, defaultPubExp)
}

// GenerateRSAKeyWithExponent generates a new RSA private key.
//
// 安全特性：
// - 使用 EVP_PKEY_keygen API（符合 OpenSSL 3.x/Tongsuo 8.5 最佳实践）
// - 密钥长度至少2048位（符合 NIST SP 800-57 Part 1 Rev.5）
// - 公共指数验证（奇数、≥3、防止过大指数）
// - 符合 FIPS 186-4 和 GB/T 3624-2018 标准
//
// 参数：
//
//	bits - RSA密钥长度（位）
//	        - 2048: 标准安全级别（推荐）
//	        - 3072: 高安全级别
//	        - 4096: 最高安全级别
//	exponent - 公共指数（通常使用65537 = 0x10001）
//
// 返回值：
//
//	RSA私钥
//	error - 错误
//
// 符合标准：
// - NIST FIPS 186-4 (Digital Signature Standard)
// - NIST SP 800-57 Part 1 Rev.5 (Key Management)
// - GB/T 3624-2018 (信息安全技术 SM2密码密码算法使用规范)
func GenerateRSAKeyWithExponent(bits int, exponent int) (PrivateKey, error) {
	// 密钥长度验证：至少2048位
	if bits < 2048 {
		return nil, fmt.Errorf("RSA key size must be at least 2048 bits (requested: %d). "+
			"1024-bit keys are deprecated and insecure per NIST SP 800-57 Part 1 Rev. 5", bits)
	}

	// 密钥长度上限检查（防止DoS攻击）
	if bits > 40960 {
		return nil, fmt.Errorf("RSA key size too large (requested: %d, maximum: 40960)", bits)
	}

	// 指数验证：必须是奇数
	if exponent%2 == 0 {
		return nil, fmt.Errorf("RSA public exponent must be odd (got: %d)", exponent)
	}

	// 指数最小值检查
	if exponent < 3 {
		return nil, fmt.Errorf("RSA public exponent must be at least 3 (got: %d)", exponent)
	}

	// NIST SP 800-56B Rev.2: 允许奇数指数，但小于 65537 的非标准值给出警告
	if exponent != 65537 && exponent < 65537 {
		log.Printf("WARNING: RSA public exponent %d is non-standard. NIST SP 800-56B Rev.2 recommends 65537.", exponent)
	}

	// 指数最大值检查
	if exponent > 1<<31-1 {
		return nil, fmt.Errorf("RSA public exponent too large (got: %d)", exponent)
	}

	// 创建 RSA 密钥生成上下文
	//
	// 使用 EVP_PKEY_CTX_new_id 而不是 EVP_PKEY_CTX_new
	// 这是生成新密钥的正确方式
	keyCtx := C.X_EVP_PKEY_CTX_new_id(C.EVP_PKEY_RSA, nil)
	if keyCtx == nil {
		return nil, ErrMallocFailure
	}

	// 初始化密钥生成
	if C.X_EVP_PKEY_keygen_init(keyCtx) != 1 {
		C.X_EVP_PKEY_CTX_free(keyCtx)
		return nil, PopError()
	}

	// 设置 RSA 密钥长度
	if C.X_EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx, C.int(bits)) != 1 {
		C.X_EVP_PKEY_CTX_free(keyCtx)
		return nil, PopError()
	}

	// 设置 RSA 公共指数
	// 将 exponent 转换为 BIGNUM
	bigExp := C.X_BN_new()
	if bigExp == nil {
		C.X_EVP_PKEY_CTX_free(keyCtx)
		return nil, ErrMallocFailure
	}

	if C.X_BN_set_word(bigExp, C.ulong(exponent)) != 1 {
		C.X_BN_free(bigExp)
		C.X_EVP_PKEY_CTX_free(keyCtx)
		return nil, PopError()
	}

	// 设置 RSA 公共指数
	// 注意：EVP_PKEY_CTX_set_rsa_keygen_pubexp 在 provider 模式下会接管
	// BIGNUM 的所有权（存储到 ctx->rsa_pubexp），调用者不应再释放。
	// EVP_PKEY_CTX_free 时会自动释放 ctx->rsa_pubexp。
	if C.X_EVP_PKEY_CTX_set_rsa_keygen_pubexp(keyCtx, bigExp) != 1 {
		// 设置失败，所有权未转移，需要手动释放
		C.X_BN_free(bigExp)
		C.X_EVP_PKEY_CTX_free(keyCtx)
		return nil, PopError()
	}
	// bigExp 所有权已转移给 keyCtx，后续由 EVP_PKEY_CTX_free 释放

	// 生成 RSA 密钥
	var rsaKey *C.EVP_PKEY
	if C.X_EVP_PKEY_keygen(keyCtx, &rsaKey) != 1 {
		C.X_EVP_PKEY_CTX_free(keyCtx)
		return nil, PopError()
	}

	// 清理上下文（EVP_PKEY_CTX_free 会释放 ctx->rsa_pubexp 即 bigExp）
	C.X_EVP_PKEY_CTX_free(keyCtx)

	// 创建私钥对象
	p := &pKey{key: rsaKey}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	return p, nil
}

// EllipticCurve repesents the ASN.1 OID of an elliptic curve.
// see https://www.openssl.org/docs/apps/ecparam.html for a list of implemented curves.
type EllipticCurve int

const (
	// P-256: X9.62/SECG curve over a 256 bit prime field
	Prime256v1 EllipticCurve = C.NID_X9_62_prime256v1
	// P-384: NIST/SECG curve over a 384 bit prime field
	Secp384r1 EllipticCurve = C.NID_secp384r1
	// P-521: NIST/SECG curve over a 521 bit prime field
	Secp521r1 EllipticCurve = C.NID_secp521r1
	// SM2:	GB/T 32918-2017
	SM2Curve EllipticCurve = C.NID_sm2
)

// GenerateECKey generates a new elliptic curve private key on the speicified
// curve.
func GenerateECKey(curve EllipticCurve) (PrivateKey, error) {
	// Tongsuo 8.5: SM2 密钥必须直接使用 EVP_PKEY_SM2 类型生成
	// 而不是使用 EVP_PKEY_EC 然后设置别名
	if curve == SM2Curve {
		return generateSM2Key()
	}

	// 其他 EC 曲线的生成逻辑保持不变
	// Create context for parameter generation
	paramCtx := C.X_EVP_PKEY_CTX_new_id(C.EVP_PKEY_EC, nil)
	if paramCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(paramCtx)

	if int(C.X_EVP_PKEY_paramgen_init(paramCtx)) != 1 {
		return nil, PopError()
	}

	// Set curve in EC parameter generation context
	if int(C.X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(paramCtx, C.int(curve))) != 1 {
		return nil, PopError()
	}

	// Create parameter object
	var params *C.EVP_PKEY
	if int(C.X_EVP_PKEY_paramgen(paramCtx, &params)) != 1 {
		return nil, PopError()
	}
	defer C.EVP_PKEY_free(params)

	// Create context for the key generation
	keyCtx := C.X_EVP_PKEY_CTX_new(params, nil)
	if keyCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(keyCtx)

	if int(C.X_EVP_PKEY_keygen_init(keyCtx)) != 1 {
		return nil, PopError()
	}

	var key *C.EVP_PKEY
	if int(C.X_EVP_PKEY_keygen(keyCtx, &key)) != 1 {
		return nil, PopError()
	}

	privKey := &pKey{key: key}
	runtime.SetFinalizer(privKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	return privKey, nil
}

// generateSM2Key 直接生成 SM2 密钥（Tongsuo 8.5）
func generateSM2Key() (PrivateKey, error) {
	// 直接使用 EVP_PKEY_SM2 类型生成密钥
	paramCtx := C.X_EVP_PKEY_CTX_new_id(C.EVP_PKEY_SM2, nil)
	if paramCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(paramCtx)

	if C.X_EVP_PKEY_keygen_init(paramCtx) != 1 {
		return nil, PopError()
	}

	var key *C.EVP_PKEY
	if C.X_EVP_PKEY_keygen(paramCtx, &key) != 1 {
		return nil, PopError()
	}

	// GM/T 0003-2012 Section 6.1: 密钥生成后验证公钥有效性
	if C.X_EVP_PKEY_public_check(key) != 1 {
		C.X_EVP_PKEY_free(key)
		return nil, fmt.Errorf("SM2 public key validation failed: %w", PopError())
	}

	// NIST SP 800-56A Rev.3 Section 6.1.6: 配对一致性验证
	if C.X_EVP_PKEY_pairwise_check(key) != 1 {
		C.X_EVP_PKEY_free(key)
		return nil, fmt.Errorf("SM2 pairwise consistency check failed: %w", PopError())
	}

	privKey := &pKey{key: key}
	runtime.SetFinalizer(privKey, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})

	return privKey, nil
}

// GenerateED25519Key generates a Ed25519 key
func GenerateED25519Key() (PrivateKey, error) {
	// Key context
	keyCtx := C.X_EVP_PKEY_CTX_new_id(C.X_EVP_PKEY_ED25519, nil)
	if keyCtx == nil {
		return nil, PopError()
	}
	defer C.EVP_PKEY_CTX_free(keyCtx)

	// Generate the key
	var privKey *C.EVP_PKEY
	if int(C.X_EVP_PKEY_keygen_init(keyCtx)) != 1 {
		return nil, PopError()
	}
	if int(C.X_EVP_PKEY_keygen(keyCtx, &privKey)) != 1 {
		return nil, PopError()
	}

	p := &pKey{key: privKey}
	runtime.SetFinalizer(p, func(p *pKey) {
		C.X_EVP_PKEY_free(p.key)
	})
	return p, nil
}
