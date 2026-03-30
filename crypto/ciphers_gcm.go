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

// #include <openssl/evp.h>
import "C"

import (
	"fmt"
	"runtime"
)

type AuthenticatedEncryptionCipherCtx interface {
	EncryptionCipherCtx

	// data passed in to ExtraData() is part of the final output; it is
	// not encrypted itself, but is part of the authenticated data. when
	// decrypting or authenticating, pass back with the decryption
	// context's ExtraData()
	ExtraData(extra []byte) error

	// use after finalizing encryption to get the authenticating tag
	GetTag() ([]byte, error)
}

type AuthenticatedDecryptionCipherCtx interface {
	DecryptionCipherCtx

	// pass in any extra data that was added during encryption with the
	// encryption context's ExtraData()
	ExtraData(extra []byte) error

	// use before finalizing decryption to tell the library what the
	// tag is expected to be
	SetTag(tag []byte) error
}

type authEncryptionCipherCtx struct {
	*encryptionCipherCtx
}

type authDecryptionCipherCtx struct {
	*decryptionCipherCtx
}

func getGCMCipher(blocksize int) (*Cipher, error) {
	var cipherptr *C.EVP_CIPHER
	switch blocksize {
	case 256:
		cipherptr = C.EVP_aes_256_gcm()
	case 192:
		cipherptr = C.EVP_aes_192_gcm()
	case 128:
		cipherptr = C.EVP_aes_128_gcm()
	default:
		return nil, ErrUknownBlockSize
	}
	return &Cipher{ptr: cipherptr}, nil
}

func NewGCMEncryptionCipherCtx(blocksize int, key, iv []byte) (
	AuthenticatedEncryptionCipherCtx, error,
) {
	// 安全建议（NIST SP 800-38D Section 8）2.1）：
	//   GCM IV 推荐长度为 96 位（12 字节），非标准长度虽可工作但会引入额外 GHASH 开销。
	//   诏次加密操作应使用唯一 IV，推荐使用 gcm_security.go 中的 NewSecureGCMEncryptionCipherCtx
	//   自动管理 IV 唯一性。
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return nil, err
	}
	ctx, err := newEncryptionCipherCtx(cipher, key, nil)
	if err != nil {
		return nil, err
	}
	if len(iv) > 0 {
		// 注意：IV 重用检测已移至 NewSecureGCMEncryptionCipherCtx
		// 底层 NewGCMEncryptionCipherCtx 保持原始行为以确保 API 兼容性

		err := ctx.SetCtrl(C.EVP_CTRL_GCM_SET_IVLEN, len(iv))
		if err != nil {
			return nil, fmt.Errorf("GCM IV configuration failed: %w", err)
		}
		if C.EVP_EncryptInit_ex(ctx.ctx, nil, nil, nil, (*C.uchar)(&iv[0])) != 1 {
			return nil, fmt.Errorf("GCM IV configuration failed: %w", PopError())
		}
	}
	return &authEncryptionCipherCtx{encryptionCipherCtx: ctx}, nil
}

func NewGCMDecryptionCipherCtx(blocksize int, key, iv []byte) (
	AuthenticatedDecryptionCipherCtx, error,
) {
	cipher, err := getGCMCipher(blocksize)
	if err != nil {
		return nil, err
	}
	ctx, err := newDecryptionCipherCtx(cipher, key, nil)
	if err != nil {
		return nil, err
	}
	if len(iv) > 0 {
		// 注意：解密侧不做 IV 重用检测
		// 正常使用场景中加密和解密必然使用相同 IV
		// IV 重用检测仅在加密侧生效（防止同一 IV 加密不同明文）

		err := ctx.SetCtrl(C.EVP_CTRL_GCM_SET_IVLEN, len(iv))
		if err != nil {
			return nil, fmt.Errorf("GCM IV configuration failed: %w", err)
		}
		if C.EVP_DecryptInit_ex(ctx.ctx, nil, nil, nil, (*C.uchar)(&iv[0])) != 1 {
			return nil, fmt.Errorf("GCM IV configuration failed: %w", PopError())
		}
	}
	return &authDecryptionCipherCtx{decryptionCipherCtx: ctx}, nil
}

func (ctx *authEncryptionCipherCtx) ExtraData(aad []byte) error {
	if aad == nil || len(aad) == 0 {
		return nil
	}
	if len(aad) > maxInt32 {
		return fmt.Errorf("AAD too large: %d bytes (maximum %d)", len(aad), maxInt32)
	}
	var outlen C.int
	if C.EVP_EncryptUpdate(ctx.ctx, nil, &outlen, (*C.uchar)(&aad[0]), C.int(len(aad))) != 1 {
		return fmt.Errorf("failed to add additional authenticated data: %w", PopError())
	}
	runtime.KeepAlive(aad)
	return nil
}

func (ctx *authDecryptionCipherCtx) ExtraData(aad []byte) error {
	if aad == nil || len(aad) == 0 {
		return nil
	}
	if len(aad) > maxInt32 {
		return fmt.Errorf("AAD too large: %d bytes (maximum %d)", len(aad), maxInt32)
	}
	var outlen C.int
	if C.EVP_DecryptUpdate(ctx.ctx, nil, &outlen, (*C.uchar)(&aad[0]), C.int(len(aad))) != 1 {
		return fmt.Errorf("failed to add additional authenticated data: %w", PopError())
	}
	runtime.KeepAlive(aad)
	return nil
}

func (ctx *authEncryptionCipherCtx) GetTag() ([]byte, error) {
	return ctx.GetCtrlBytes(C.EVP_CTRL_GCM_GET_TAG, GCMTagMaxLen,
		GCMTagMaxLen)
}

func (ctx *authDecryptionCipherCtx) SetTag(tag []byte) error {
	return ctx.SetCtrlBytes(C.EVP_CTRL_GCM_SET_TAG, len(tag), tag)
}
