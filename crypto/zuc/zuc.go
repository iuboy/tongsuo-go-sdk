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

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	// KeySize ZUC 密钥长度 (16 字节 = 128 位)
	KeySize = 16

	// IVSize ZUC IV 长度 (5 字节)
	IVSize = 5
)

// zucCipher 封装 ZUC EVP_CIPHER 流密码
type zucCipher struct {
	ptr *C.EVP_CIPHER
}

func newZUCCipher() (*zucCipher, error) {
	c := C.EVP_eea3()
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
