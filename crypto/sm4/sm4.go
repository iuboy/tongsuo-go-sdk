// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm4

// #include "shim.h"
import "C"

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"log"
	"os"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	BlockSize = 16
	KeySize   = 16

	sm4GCMTagLen   = 16
	sm4CCMTagLen   = 12
	sm4GCMMinIVLen = 12
)

// 安全模式配置
// 通过环境变量 TONGSUO_ALLOW_UNSAFE_MODES=true 允许使用不安全的加密模式
// 生产环境强烈建议保持禁用状态
// 使用 atomic.Bool 保证并发读写的线程安全
var allowUnsafeModes atomic.Bool

func init() {
	v := os.Getenv("TONGSUO_ALLOW_UNSAFE_MODES")
	allowUnsafeModes.Store(v == "true" || v == "1")
}

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
	mode int
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
	encPool *sync.Pool
	decPool *sync.Pool
	key     []byte
}

// evpCtx 包装 EVP_CIPHER_CTX，确保 C 内存通过 Go GC 正确释放。
// sync.Pool 在 GC 时可能丢弃所有缓存项，如果不为每个 C 上下文
// 设置 finalizer，会导致 EVP_CIPHER_CTX 内存泄漏。
type evpCtx struct {
	ctx *C.EVP_CIPHER_CTX
}

func newEvpCtx() *evpCtx {
	ctx := C.EVP_CIPHER_CTX_new()
	if ctx == nil {
		panic("sm4: failed to create EVP_CIPHER_CTX")
	}
	e := &evpCtx{ctx: ctx}
	runtime.SetFinalizer(e, func(e *evpCtx) {
		if e.ctx != nil {
			C.EVP_CIPHER_CTX_free(e.ctx)
			e.ctx = nil
		}
	})
	return e
}

func (c *sm4Cipher) BlockSize() int {
	return BlockSize
}

func NewCipher(key []byte) (cipher.Block, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid key size: %w", crypto.ErrInvalidKeySize)
	}

	// 安全警告：cipher.Block 接口本身提供原始 ECB 块加密能力，
	// 但 Go 标准库（cipher.NewGCM、cipher.NewCBCDecrypter 等）会在其上构建安全模式。
	// 仅在直接使用 Encrypt/Decrypt 方法（即 ECB 模式）时存在安全风险。
	// 此处打印警告以提醒调用方不要直接使用 ECB 模式。
	allowUnsafe := allowUnsafeModes.Load()
	if !allowUnsafe {
		log.Println("WARNING: sm4.NewCipher() provides raw cipher.Block interface. " +
			"Direct Encrypt/Decrypt calls use ECB mode which is insecure. " +
			"Use Go standard library modes (cipher.NewGCM, cipher.NewCBCDecrypter, etc.) " +
			"or sm4.NewEncrypter/NewDecrypter with CipherModeGCM/CBC instead. " +
			"Set TONGSUO_ALLOW_UNSAFE_MODES=1 to suppress this warning.")
	}

	// 复制密钥以确保安全
	keyCopy := make([]byte, KeySize)
	copy(keyCopy, key)

	c := &sm4Cipher{
		key: keyCopy,
		encPool: &sync.Pool{
			New: func() interface{} {
				return newEvpCtx()
			},
		},
		decPool: &sync.Pool{
			New: func() interface{} {
				return newEvpCtx()
			},
		},
	}

	runtime.SetFinalizer(c, func(c *sm4Cipher) {
		for i := range c.key {
			c.key[i] = 0
		}
	})

	return c, nil
}

// Encrypt 使用 ECB 模式加密单个块
//
// 注意：此方法符合 Go cipher.Block 接口规范，该接口不允许返回错误。
// panic 仅在以下不可恢复的情况下发生：
// - 输入/输出缓冲区不足（调用方编程错误）
// - EVP 操作失败（系统资源耗尽，极不可能）
//
// 调用方应确保传入完整的 16 字节块以避免 panic
func (c *sm4Cipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}

	ectx := c.encPool.Get().(*evpCtx)
	defer func() {
		C.X_EVP_CIPHER_CTX_reset(ectx.ctx)
		c.encPool.Put(ectx)
	}()

	ctx := ectx.ctx
	cipher := C.EVP_sm4_ecb()
	if C.X_EVP_EncryptInit_ex(ctx, cipher, nil, (*C.uchar)(&c.key[0]), nil) != 1 {
		panic("sm4: cipher operation failed")
	}

	C.X_EVP_CIPHER_CTX_set_padding(ctx, 0)

	var outLen C.int
	if C.X_EVP_EncryptUpdate(ctx, (*C.uchar)(&dst[0]), &outLen, (*C.uchar)(&src[0]), BlockSize) != 1 {
		panic("sm4: cipher operation failed")
	}

	var tmpBuf [1]byte
	var finalLen C.int
	if C.X_EVP_EncryptFinal_ex(ctx, (*C.uchar)(&tmpBuf[0]), &finalLen) != 1 {
		panic("sm4: cipher operation failed")
	}
	if finalLen != 0 {
		panic("sm4: cipher operation failed")
	}
}

// Decrypt 使用 ECB 模式解密单个块
//
// 注意：此方法符合 Go cipher.Block 接口规范，该接口不允许返回错误。
// panic 仅在以下不可恢复的情况下发生（同 Encrypt）
func (c *sm4Cipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("sm4: input not full block")
	}
	if len(dst) < BlockSize {
		panic("sm4: output not full block")
	}

	ectx := c.decPool.Get().(*evpCtx)
	defer func() {
		C.X_EVP_CIPHER_CTX_reset(ectx.ctx)
		c.decPool.Put(ectx)
	}()

	ctx := ectx.ctx
	cipher := C.EVP_sm4_ecb()
	if C.X_EVP_DecryptInit_ex(ctx, cipher, nil, (*C.uchar)(&c.key[0]), nil) != 1 {
		panic("sm4: cipher operation failed")
	}

	C.X_EVP_CIPHER_CTX_set_padding(ctx, 0)

	var outLen C.int
	if C.X_EVP_DecryptUpdate(ctx, (*C.uchar)(&dst[0]), &outLen, (*C.uchar)(&src[0]), BlockSize) != 1 {
		panic("sm4: cipher operation failed")
	}

	var tmpBuf [1]byte
	var finalLen C.int
	if C.X_EVP_DecryptFinal_ex(ctx, (*C.uchar)(&tmpBuf[0]), &finalLen) != 1 {
		panic("sm4: cipher operation failed")
	}
	if finalLen != 0 {
		panic("sm4: cipher operation failed")
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
	// 密钥长度验证（GB/T 32907-2016: SM4 密钥固定 16 字节）
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid SM4 key size: %d bytes (expected %d): %w",
			len(key), KeySize, crypto.ErrInvalidKeySize)
	}

	// IV 长度验证
	if needsIV(mode) && len(iv) == 0 {
		return nil, fmt.Errorf("SM4 mode %d requires a non-empty IV: %w", mode, crypto.ErrNilParameter)
	}

	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	// CCM/GCM 需要先设置 IV 长度再设置 IV（同 NewEncrypter）
	var cctx crypto.DecryptionCipherCtx
	if (mode == crypto.CipherModeGCM || mode == crypto.CipherModeCCM) && len(iv) > 0 {
		cctx, err = crypto.NewDecryptionCipherCtx(cipher, key, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryption cipher ctx %w", err)
		}
		err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
		if err != nil {
			return nil, fmt.Errorf("failed to set IV len to %d: %w", len(iv), err)
		}
		err = cctx.SetKeyAndIV(nil, iv)
		if err != nil {
			return nil, fmt.Errorf("could not set IV: %w", err)
		}
	} else {
		cctx, err = crypto.NewDecryptionCipherCtx(cipher, key, iv)
		if err != nil {
			return nil, fmt.Errorf("failed to create decryption cipher ctx %w", err)
		}
	}

	// 防御性复制密钥和 IV，避免调用方保留引用导致密钥材料泄露
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	dec := &sm4Decrypter{cctx: cctx, key: keyCopy, iv: ivCopy, aad: nil, tag: nil, mode: mode}
	runtime.SetFinalizer(dec, func(d *sm4Decrypter) { d.Close() })
	return dec, nil
}

func (ctx *sm4Decrypter) SetPadding(pad bool) {
	ctx.cctx.SetPadding(pad)
}

// Close 安全清零密钥、IV 和 tag 等敏感材料
//
// 符合 NIST SP 800-57 Part 1 Rev.5 Section 5.3.4：
// 密钥材料在不再使用时应被安全擦除
func (ctx *sm4Decrypter) Close() {
	crypto.ZeroBytes(ctx.key)
	crypto.ZeroBytes(ctx.iv)
	crypto.ZeroBytes(ctx.aad)
	crypto.ZeroBytes(ctx.tag)
}

func NewEncrypter(mode int, key []byte, iv []byte) (Encrypter, error) {
	// 密钥长度验证（GB/T 32907-2016: SM4 密钥固定 16 字节）
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid SM4 key size: %d bytes (expected %d): %w",
			len(key), KeySize, crypto.ErrInvalidKeySize)
	}

	// IV 长度验证
	if needsIV(mode) && len(iv) == 0 {
		return nil, fmt.Errorf("SM4 mode %d requires a non-empty IV: %w", mode, crypto.ErrNilParameter)
	}

	// NIST SP 800-38D Section 8: GCM IV 推荐长度 12 字节
	if mode == crypto.CipherModeGCM && len(iv) > 0 && len(iv) < sm4GCMMinIVLen {
		return nil, fmt.Errorf("SM4-GCM IV too short: %w", crypto.ErrBadIvSize)
	}

	var tagLen int

	cipher, err := getSM4Cipher(mode)
	if err != nil {
		return nil, err
	}

	if mode == crypto.CipherModeGCM {
		tagLen = sm4GCMTagLen
	}
	if mode == crypto.CipherModeCCM {
		tagLen = sm4CCMTagLen
	}

	// CCM/GCM 需要先设置 IV 长度再设置 IV
	// CCM init 后 ctx.IVSize() 为 7，但实际 IV 可能是 12 字节
	// 如果直接传 iv 给 NewEncryptionCipherCtx，SetKeyAndIV 会检查长度不匹配
	var cctx crypto.EncryptionCipherCtx
	if (mode == crypto.CipherModeGCM || mode == crypto.CipherModeCCM) && len(iv) > 0 {
		// 先不传 IV 创建上下文
		cctx, err = crypto.NewEncryptionCipherCtx(cipher, key, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryption cipher ctx %w", err)
		}
		// 设置 IV 长度
		err := cctx.SetCtrl(C.EVP_CTRL_AEAD_SET_IVLEN, len(iv))
		if err != nil {
			return nil, fmt.Errorf("could not set IV len to %d: %w", len(iv), err)
		}
		// 再设置 IV
		err = cctx.SetKeyAndIV(nil, iv)
		if err != nil {
			return nil, fmt.Errorf("could not set IV: %w", err)
		}
	} else {
		cctx, err = crypto.NewEncryptionCipherCtx(cipher, key, iv)
		if err != nil {
			return nil, fmt.Errorf("failed to create encryption cipher ctx %w", err)
		}
	}

	// 防御性复制密钥和 IV，避免调用方保留引用导致密钥材料泄露
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	enc := &sm4Encrypter{cctx: cctx, tagLen: tagLen, key: keyCopy, iv: ivCopy, aad: nil}
	runtime.SetFinalizer(enc, func(e *sm4Encrypter) { e.Close() })
	return enc, nil
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

// Close 安全清零密钥和 IV 等敏感材料
//
// 符合 NIST SP 800-57 Part 1 Rev.5 Section 5.3.4：
// 密钥材料在不再使用时应被安全擦除
func (ctx *sm4Encrypter) Close() {
	crypto.ZeroBytes(ctx.key)
	crypto.ZeroBytes(ctx.iv)
	crypto.ZeroBytes(ctx.aad)
}

func (ctx *sm4Encrypter) SetAAD(aad []byte) {
	if aad == nil {
		ctx.aad = nil
		return
	}
	// 防御性拷贝，防止调用方通过修改原切片篡改AAD（C-04 修复）
	ctx.aad = make([]byte, len(aad))
	copy(ctx.aad, aad)
}

func (ctx *sm4Decrypter) SetAAD(aad []byte) {
	if aad == nil {
		ctx.aad = nil
		return
	}
	// 防御性拷贝，防止调用方通过修改原切片篡改AAD（C-04 修复）
	ctx.aad = make([]byte, len(aad))
	copy(ctx.aad, aad)
}

func (ctx *sm4Decrypter) SetTag(tag []byte) {
	ctx.tag = tag
}

func (ctx *sm4Decrypter) DecryptAll(src []byte) ([]byte, error) {
	// AEAD 模式安全检查：GCM/CCM 解密必须设置 tag
	// 符合 NIST SP 800-38D Section 7.2：AEAD 解密必须验证认证标签
	// 不验证 tag 会导致密文被静默接受，破坏认证加密安全性
	if ctx.tag == nil {
		cipherFlags := C.EVP_CIPHER_flags(C.X_EVP_CIPHER_CTX_cipher(
			(*C.EVP_CIPHER_CTX)(ctx.cctx.Ctx())))
		mode := cipherFlags & C.EVP_CIPH_MODE
		if mode == C.EVP_CIPH_GCM_MODE || mode == C.EVP_CIPH_CCM_MODE {
			return nil, fmt.Errorf("sm4: AEAD decryption requires authentication tag (call SetTag first): %w",
				crypto.ErrNilParameter)
		}
	}

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

// needsIV 判断给定模式是否需要 IV
func needsIV(mode int) bool {
	switch mode {
	case crypto.CipherModeCBC, crypto.CipherModeCFB,
		crypto.CipherModeOFB, crypto.CipherModeCTR,
		crypto.CipherModeGCM, crypto.CipherModeCCM:
		return true
	default:
		return false
	}
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
