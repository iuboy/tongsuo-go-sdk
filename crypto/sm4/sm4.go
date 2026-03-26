// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm4

// #include "../shim.h"
import "C"

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"os"
	"sync"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	BlockSize = 16
	KeySize   = 16
)

// 安全模式配置
// 通过环境变量 TONGSUO_ALLOW_UNSAFE_MODES=1 允许使用不安全的加密模式
// 生产环境强烈建议保持禁用状态
var allowUnsafeModes = os.Getenv("TONGSUO_ALLOW_UNSAFE_MODES") == "true"

type Encrypter interface {
	// crypto.EncryptionCipherCtx
	SetPadding(pad bool)
	EncryptAll(input []byte) ([]byte, error)
	SetAAD(aad []byte)
	SetTagLen(length int)
	GetTag() ([]byte, error)
}

type Decrypter interface {
	// crypto.DecryptionCipherCtx
	SetPadding(pad bool)
	DecryptAll(input []byte) ([]byte, error)
	SetAAD(aad []byte)
	SetTag(tag []byte)
}

type sm4Encrypter struct {
	cctx   crypto.EncryptionCipherCtx
	key    []byte
	iv     []byte
	aad    []byte
	tagLen int
}

type sm4Decrypter struct {
	cctx crypto.DecryptionCipherCtx
	key  []byte
	iv   []byte
	aad  []byte
	tag  []byte
}

// sm4Cipher 实现 cipher.Block 接口
//
// 安全警告：
// - 此接口使用 ECB 模式，ECB 模式无法隐藏明文模式，相同明文块产生相同密文块
// - ECB 模式不具备完整性保护，易受篡改攻击
// - 不建议在生产环境直接使用此接口
//
// 推荐方案：
// - 使用 sm4.NewEncrypter/NewDecrypter 配合 GCM 模式（提供 AEAD 认证加密）
// - 使用 sm4.NewEncrypter/NewDecrypter 配合 CBC 模式（需要额外的 MAC）
//
// 参考：GB/T 17929-2012, GM/T 0022-2014, NIST SP 800-38A
type sm4Cipher struct {
	// 使用 sync.Pool 复用 EVP_CIPHER_CTX 以提高性能
	// 每个上下文在获取时设置密钥
	encPool *sync.Pool
	decPool *sync.Pool
	key     []byte
}

func (c *sm4Cipher) BlockSize() int {
	return BlockSize
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: %w", crypto.ErrInvalidKeySize)
	}

	// 安全检查：ECB模式在默认情况下被禁用
	// 必须显式启用环境变量才能使用
	if !allowUnsafeModes {
		return nil, fmt.Errorf("ECB mode is insecure and disabled by default\n\n" +
			"Security Risks:\n" +
			"- ECB mode does not hide plaintext patterns (identical plaintext blocks produce identical ciphertext blocks)\n" +
			"- ECB mode is vulnerable to pattern analysis and chosen-plaintext attacks\n" +
			"- ECB mode is not compliant with NIST SP 800-38A or GM/T standards\n\n" +
			"Recommended Alternatives:\n" +
			"- Use sm4.NewEncrypter() with CipherModeGCM (provides AEAD authentication)\n" +
			"- Use sm4.NewEncrypter() with CipherModeCBC (requires additional MAC for integrity)\n" +
			"- Use Go's cipher.NewGCM() with sm4.NewCipher() for AEAD encryption\n\n" +
			"To enable unsafe modes (not recommended):\n" +
			"  Set environment variable: TONGSUO_ALLOW_UNSAFE_MODES=1\n" +
			"  Warning: Only use in test environments or when compatibility with legacy systems is required")
	}

	// 复制密钥以确保安全
	keyCopy := make([]byte, KeySize)
	copy(keyCopy, key)

	c := &sm4Cipher{
		key: keyCopy,
		encPool: &sync.Pool{
			New: func() interface{} {
				ctx := C.EVP_CIPHER_CTX_new()
				if ctx == nil {
					panic("sm4: failed to create EVP_CIPHER_CTX")
				}
				return ctx
			},
		},
		decPool: &sync.Pool{
			New: func() interface{} {
				ctx := C.EVP_CIPHER_CTX_new()
				if ctx == nil {
					panic("sm4: failed to create EVP_CIPHER_CTX")
				}
				return ctx
			},
		},
	}

	return c, nil
}

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}

	// 从池中获取上下文
	ctx := c.encPool.Get().(*C.EVP_CIPHER_CTX)
	defer c.encPool.Put(ctx)

	// 使用 EVP API 进行 ECB 模式单块加密
	cipher := C.EVP_sm4_ecb()
	if C.X_EVP_EncryptInit_ex(ctx, cipher, nil, (*C.uchar)(&c.key[0]), nil) != 1 {
		panic("sm4: EVP_EncryptInit_ex failed")
	}

	// 禁用 padding（处理单块）
	C.X_EVP_CIPHER_CTX_set_padding(ctx, 0)

	var outLen C.int
	if C.X_EVP_EncryptUpdate(ctx, (*C.uchar)(&dst[0]), &outLen, (*C.uchar)(&src[0]), BlockSize) != 1 {
		panic("sm4: EVP_EncryptUpdate failed")
	}

	// 对于禁用 padding 的完整块，Final 不应该输出数据
	// 使用临时缓冲区以确保安全
	var tmpBuf [1]byte
	var finalLen C.int
	if C.X_EVP_EncryptFinal_ex(ctx, (*C.uchar)(&tmpBuf[0]), &finalLen) != 1 {
		panic("sm4: EVP_EncryptFinal_ex failed")
	}
	if finalLen != 0 {
		panic("sm4: unexpected output from EncryptFinal_ex")
	}
}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}

	// 从池中获取上下文
	ctx := c.decPool.Get().(*C.EVP_CIPHER_CTX)
	defer c.decPool.Put(ctx)

	// 使用 EVP API 进行 ECB 模式单块解密
	cipher := C.EVP_sm4_ecb()
	if C.X_EVP_DecryptInit_ex(ctx, cipher, nil, (*C.uchar)(&c.key[0]), nil) != 1 {
		panic("sm4: EVP_DecryptInit_ex failed")
	}

	// 禁用 padding（处理单块）
	C.X_EVP_CIPHER_CTX_set_padding(ctx, 0)

	var outLen C.int
	if C.X_EVP_DecryptUpdate(ctx, (*C.uchar)(&dst[0]), &outLen, (*C.uchar)(&src[0]), BlockSize) != 1 {
		panic("sm4: EVP_DecryptUpdate failed")
	}

	// 对于禁用 padding 的完整块，Final 不应该输出数据
	// 使用临时缓冲区以确保安全
	var tmpBuf [1]byte
	var finalLen C.int
	if C.X_EVP_DecryptFinal_ex(ctx, (*C.uchar)(&tmpBuf[0]), &finalLen) != 1 {
		panic("sm4: EVP_DecryptFinal_ex failed")
	}
	if finalLen != 0 {
		panic("sm4: unexpected output from DecryptFinal_ex")
	}
}

func getSM4Cipher(mode int) (*crypto.Cipher, error) {
	var cipher *crypto.Cipher
	var err error

	switch mode {
	case crypto.CipherModeECB:
		cipher, err = crypto.GetCipherByName("SM4-ECB")
	case crypto.CipherModeCBC:
		cipher, err = crypto.GetCipherByName("SM4-CBC")
	case crypto.CipherModeCFB:
		cipher, err = crypto.GetCipherByName("SM4-CFB")
	case crypto.CipherModeOFB:
		cipher, err = crypto.GetCipherByName("SM4-OFB")
	case crypto.CipherModeCTR:
		cipher, err = crypto.GetCipherByName("SM4-CTR")
	case crypto.CipherModeGCM:
		cipher, err = crypto.GetCipherByName("SM4-GCM")
	case crypto.CipherModeCCM:
		cipher, err = crypto.GetCipherByName("SM4-CCM")
	default:
		return nil, fmt.Errorf("unsupported sm4 mode: %w", crypto.ErrUnsupportedMode)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get cipher: %w", err)
	}

	return cipher, nil
}

func NewDecrypter(mode int, key []byte, iv []byte) (Decrypter, error) {
	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	cctx, err := crypto.NewDecryptionCipherCtx(cipher, key, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption cipher ctx %w", err)
	}

	if len(iv) > 0 {
		if mode == crypto.CipherModeGCM || mode == crypto.CipherModeCCM {
			err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("failed to set IV len to %d: %w", len(iv), err)
			}
		}
	}

	return &sm4Decrypter{cctx: cctx, key: key, iv: iv, aad: nil, tag: nil}, nil
}

func (ctx *sm4Decrypter) SetPadding(pad bool) {
	ctx.cctx.SetPadding(pad)
}

func NewEncrypter(mode int, key []byte, iv []byte) (Encrypter, error) {
	var tagLen int

	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	if mode == crypto.CipherModeGCM {
		tagLen = 16
	}
	if mode == crypto.CipherModeCCM {
		tagLen = 12
	}

	cctx, err := crypto.NewEncryptionCipherCtx(cipher, key, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption cipher ctx %w", err)
	}

	if len(iv) > 0 {
		if mode == crypto.CipherModeGCM || mode == crypto.CipherModeCCM {
			err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
			if err != nil {
				return nil, fmt.Errorf("could not set IV len to %d: %w", len(iv), err)
			}
		}
	}

	return &sm4Encrypter{cctx: cctx, tagLen: tagLen, key: key, iv: iv, aad: nil}, nil
}

func (ctx *sm4Encrypter) GetTag() ([]byte, error) {
	tag, err := ctx.cctx.GetCtrlBytes(C.EVP_CTRL_AEAD_GET_TAG, ctx.tagLen, ctx.tagLen)
	if err != nil {
		return nil, fmt.Errorf("failed to get tag: %w", err)
	}

	return tag, nil
}

func (ctx *sm4Encrypter) SetTagLen(length int) {
	ctx.tagLen = length
}

func (ctx *sm4Encrypter) SetPadding(pad bool) {
	ctx.cctx.SetPadding(pad)
}

func (ctx *sm4Encrypter) SetAAD(aad []byte) {
	ctx.aad = aad
}

func (ctx *sm4Decrypter) SetAAD(aad []byte) {
	ctx.aad = aad
}

func (ctx *sm4Decrypter) SetTag(tag []byte) {
	ctx.tag = tag
}

func (ctx *sm4Decrypter) DecryptAll(src []byte) ([]byte, error) {
	if ctx.tag != nil {
		err := ctx.cctx.SetCtrlBytes(C.EVP_CTRL_AEAD_SET_TAG, len(ctx.tag), ctx.tag)
		if err != nil {
			return nil, fmt.Errorf("failed to set tag: %w", err)
		}
	}

	err := ctx.cctx.SetKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv: %w", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		isCcm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()))) &
			C.EVP_CIPH_MODE) == C.EVP_CIPH_CCM_MODE

		if isCcm {
			res := C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length: %w", crypto.PopError())
			}
		}

		res := C.EVP_DecryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, (*C.uchar)(&ctx.aad[0]),
			C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to decrypt: %w", crypto.PopError())
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.cctx.DecryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("failed to perform decryption: %w", err)
	}
	res.Write(buf)

	buf2, err := ctx.cctx.DecryptFinal()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize decryption: %w", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}

func (ctx *sm4Encrypter) EncryptAll(src []byte) ([]byte, error) {
	isCcm := (C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()))) & C.EVP_CIPH_MODE) ==
		C.EVP_CIPH_CCM_MODE

	if isCcm {
		err := ctx.cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_TAG, ctx.tagLen)
		if err != nil {
			return nil, fmt.Errorf("failed to set CCM tag: %w", err)
		}
	}

	err := ctx.cctx.SetKeyAndIV(ctx.key, ctx.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to set key or iv: %w", err)
	}

	var tmplen C.int
	if ctx.aad != nil {
		if isCcm {
			res := C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, nil, C.int(len(src)))
			if res != 1 {
				return nil, fmt.Errorf("failed to set CCM plain text length: %w", crypto.PopError())
			}
		}

		res := C.EVP_EncryptUpdate((*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx()), nil, &tmplen, (*C.uchar)(&ctx.aad[0]),
			C.int(len(ctx.aad)))
		if res != 1 {
			return nil, fmt.Errorf("failed to set AAD: %w", crypto.PopError())
		}
	}

	res := new(bytes.Buffer)
	buf, err := ctx.cctx.EncryptUpdate(src)
	if err != nil {
		return nil, fmt.Errorf("failed to perform encryption: %w", err)
	}
	res.Write(buf)

	buf2, err := ctx.cctx.EncryptFinal()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize encryption: %w", err)
	}
	res.Write(buf2)

	return res.Bytes(), nil
}
