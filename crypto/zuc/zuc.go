// ZUC 祖冲之流密码封装
//
// 实现 128-EEA3 加密（EVP_CIPHER 接口）。
// 128-EIA3 完整性算法的 Tongsuo 公开 API 暂不完善，待后续补充。
//
// GM/T 0001-2012 规范:
// - ZUC-128-EEA3: 机密性算法，流密码加密
// - 密钥长度: 16 字节
// - IV 长度: 5 字节 (COUNT[4] + BEARER+DIR[1])
// - 块大小: 1 (流密码)

package zuc

// #include "shim.h"
import "C"
import (
	"crypto/cipher"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	// KeySize ZUC 密钥长度 (16 字节 = 128 位)
	KeySize = 16

	// IVSize ZUC IV 长度 (5 字节)
	IVSize = 5

	// MACSize EIA3 MAC 长度 (4 字节 = 32 位)
	MACSize = C.EIA3_DIGEST_SIZE
)

// zucCipher 封装 ZUC EVP_CIPHER 流密码
type zucCipher struct {
	ptr *C.EVP_CIPHER
}

func newZUCCipher() (*zucCipher, error) {
	c := C.X_EVP_eea3()
	if c == nil {
		return nil, fmt.Errorf("ZUC-128-EEA3 not available")
	}
	return &zucCipher{ptr: c}, nil
}

func (c *zucCipher) BlockSize() int { return 1 }

func (c *zucCipher) KeySize() int { return KeySize }

func (c *zucCipher) IVSize() int { return IVSize }

// zucEncrypter ZUC 加密器
type zucEncrypter struct {
	ctx *C.EVP_CIPHER_CTX
}

// NewEncrypter 创建 ZUC 加密器
func NewEncrypter(key, iv []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("ZUC key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("ZUC IV must be %d bytes, got %d", IVSize, len(iv))
	}

	cipher_, err := newZUCCipher()
	if err != nil {
		return nil, err
	}

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, crypto.ErrMallocFailure
	}

	e := &zucEncrypter{ctx: ctx}
	runtime.SetFinalizer(e, func(e *zucEncrypter) {
		C.EVP_CIPHER_CTX_free(e.ctx)
	})

	kptr := (*C.uchar)(&key[0])
	iptr := (*C.uchar)(&iv[0])

	if C.EVP_EncryptInit_ex(ctx, cipher_.ptr, nil, kptr, iptr) != 1 {
		return nil, fmt.Errorf("ZUC EncryptInit failed: %w", crypto.PopError())
	}

	return e, nil
}

func (e *zucEncrypter) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("zuc: dst buffer too short")
	}
	outLen := C.int(len(src))
	if C.EVP_EncryptUpdate(e.ctx, (*C.uchar)(&dst[0]), &outLen,
		(*C.uchar)(&src[0]), C.int(len(src))) != 1 {
		panic("ZUC EncryptUpdate failed")
	}
}

// zucDecrypter ZUC 解密器（流密码加解密相同）
type zucDecrypter struct {
	ctx *C.EVP_CIPHER_CTX
}

// NewDecrypter 创建 ZUC 解密器
func NewDecrypter(key, iv []byte) (cipher.Stream, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("ZUC key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("ZUC IV must be %d bytes, got %d", IVSize, len(iv))
	}

	cipher_, err := newZUCCipher()
	if err != nil {
		return nil, err
	}

	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		return nil, crypto.ErrMallocFailure
	}

	d := &zucDecrypter{ctx: ctx}
	runtime.SetFinalizer(d, func(d *zucDecrypter) {
		C.EVP_CIPHER_CTX_free(d.ctx)
	})

	kptr := (*C.uchar)(&key[0])
	iptr := (*C.uchar)(&iv[0])

	if C.EVP_DecryptInit_ex(ctx, cipher_.ptr, nil, kptr, iptr) != 1 {
		return nil, fmt.Errorf("ZUC DecryptInit failed: %w", crypto.PopError())
	}

	return d, nil
}

func (d *zucDecrypter) XORKeyStream(dst, src []byte) {
	if len(src) == 0 {
		return
	}
	if len(dst) < len(src) {
		panic("zuc: dst buffer too short")
	}
	outLen := C.int(len(src))
	if C.EVP_DecryptUpdate(d.ctx, (*C.uchar)(&dst[0]), &outLen,
		(*C.uchar)(&src[0]), C.int(len(src))) != 1 {
		panic("ZUC DecryptUpdate failed")
	}
}

// Encrypt 使用 ZUC-128-EEA3 加密数据
func Encrypt(key, iv, plaintext []byte) ([]byte, error) {
	e, err := NewEncrypter(key, iv)
	if err != nil {
		return nil, err
	}
	ciphertext := make([]byte, len(plaintext))
	e.XORKeyStream(ciphertext, plaintext)
	return ciphertext, nil
}

// Decrypt 使用 ZUC-128-EEA3 解密数据
func Decrypt(key, iv, ciphertext []byte) ([]byte, error) {
	d, err := NewDecrypter(key, iv)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	d.XORKeyStream(plaintext, ciphertext)
	return plaintext, nil
}

// Ensure interface compliance
var _ cipher.Stream = (*zucEncrypter)(nil)
var _ cipher.Stream = (*zucDecrypter)(nil)

// ---------------------------------------------------------------------------
// ZUC-128-EIA3 完整性认证算法 (GM/T 0001-2012)
// ---------------------------------------------------------------------------

// EIA3Authenticator ZUC-128-EIA3 完整性认证器
//
// GM/T 0001-2012 128-EIA3:
//   - 认证算法，生成 4 字节 MAC (Message Authentication Code)
//   - 密钥长度: 16 字节 (与 EEA3 相同)
//   - IV 长度: 5 字节 (COUNT[4] + BEARER+DIR[1])
//
// 注意: Tongsuo 的 EIA3_Update 存在 keystream 位置重置问题，
// 多次调用 Update 会产生不正确的 MAC。因此本实现采用内部缓冲，
// 在 Final 时一次性调用 C 层的 EIA3_Update。
//
// 使用方式:
//
//	a, _ := zuc.NewEIA3Authenticator(key, iv)
//	a.Update(data)
//	mac, _ := a.Final()
type EIA3Authenticator struct {
	ctx  unsafe.Pointer
	data []byte
}

// NewEIA3Authenticator 创建 EIA3 认证器
func NewEIA3Authenticator(key, iv []byte) (*EIA3Authenticator, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("EIA3 key must be %d bytes, got %d", KeySize, len(key))
	}
	if len(iv) != IVSize {
		return nil, fmt.Errorf("EIA3 IV must be %d bytes, got %d", IVSize, len(iv))
	}

	ctx := C.X_EIA3_CTX_new()
	if ctx == nil {
		return nil, fmt.Errorf("failed to allocate EIA3 context: %w", crypto.ErrMallocFailure)
	}

	a := &EIA3Authenticator{ctx: ctx}
	runtime.SetFinalizer(a, func(a *EIA3Authenticator) {
		if a.ctx != nil {
			C.X_EIA3_CTX_free(a.ctx)
		}
	})

	kptr := (*C.uchar)(&key[0])
	iptr := (*C.uchar)(&iv[0])

	if C.X_EIA3_Init(ctx, kptr, iptr) != 1 {
		runtime.SetFinalizer(a, nil)
		C.X_EIA3_CTX_free(ctx)
		return nil, fmt.Errorf("EIA3_Init failed: %w", crypto.PopError())
	}

	return a, nil
}

// Update 输入待认证数据（可多次调用，内部缓冲）
func (a *EIA3Authenticator) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}
	a.data = append(a.data, data...)
	return nil
}

// Final 完成认证计算，返回 4 字节 MAC。
// 调用后认证器不可复用。
func (a *EIA3Authenticator) Final() ([]byte, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("EIA3 context already finalized")
	}

	// 一次性调用 EIA3_Update（绕过 Tongsuo 流式 bug）
	if len(a.data) > 0 {
		if C.X_EIA3_Update(a.ctx, (*C.uchar)(&a.data[0]), C.size_t(len(a.data))) != 1 {
			return nil, fmt.Errorf("EIA3_Update failed: %w", crypto.PopError())
		}
	}

	out := make([]byte, MACSize)
	C.X_EIA3_Final(a.ctx, (*C.uchar)(&out[0]))
	C.X_EIA3_CTX_free(a.ctx)
	a.ctx = nil
	a.data = nil
	runtime.SetFinalizer(a, nil)
	return out, nil
}

// EIA3MAC 便捷函数，计算数据的 EIA3 MAC (4 字节)
func EIA3MAC(key, iv, data []byte) ([]byte, error) {
	a, err := NewEIA3Authenticator(key, iv)
	if err != nil {
		return nil, err
	}
	if err := a.Update(data); err != nil {
		return nil, err
	}
	return a.Final()
}
