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
	"crypto/subtle"
	"fmt"
	"runtime"
	"unsafe"
)

// maxHMACKeyLen HMAC 密钥最大长度（RFC 2104 无硬性限制，此处防止 DoS）
const maxHMACKeyLen = 4096

type HMAC struct {
	ctx *C.HMAC_CTX
	md  *C.EVP_MD
}

func NewHMAC(key []byte, digest DigestAlgo) (*HMAC, error) {
	// 安全验证：密钥长度检查
	if len(key) == 0 {
		return nil, fmt.Errorf("HMAC key cannot be empty")
	}

	// 安全验证：密钥长度上限（防止DoS攻击）
	if len(key) > maxHMACKeyLen {
		return nil, fmt.Errorf("HMAC key too long (max %d bytes, got %d)", maxHMACKeyLen, len(key))
	}

	var md *C.EVP_MD = getDigestFunction(digest)

	// 安全验证：摘要算法有效性
	if md == nil {
		return nil, fmt.Errorf("invalid digest algorithm: %v", digest)
	}

	hmac := &HMAC{ctx: nil, md: md}
	hmac.ctx = C.X_HMAC_CTX_new()
	if hmac.ctx == nil {
		return nil, ErrMallocFailure
	}

	if rc := C.X_HMAC_Init_ex(hmac.ctx, unsafe.Pointer(&key[0]), C.int(len(key)), md, nil); rc != 1 {
		C.X_HMAC_CTX_free(hmac.ctx)
		return nil, fmt.Errorf("failed to init HMAC_CTX: %w", PopError())
	}

	runtime.SetFinalizer(hmac, func(h *HMAC) { h.Close() })
	return hmac, nil
}

func (h *HMAC) Close() {
	if h.ctx == nil {
		return
	}
	// HMAC_CTX_free 内部会调用 OPENSSL_cleanse 清零密钥材料，
	// 但 Reset() 显式清零内部状态作为深度防御。
	// 忽略 Reset 错误：即使失败也必须释放资源。
	_ = h.Reset()
	C.X_HMAC_CTX_free(h.ctx)
	h.ctx = nil
	runtime.SetFinalizer(h, nil)
}

func (h *HMAC) Write(data []byte) (int, error) {
	if h.ctx == nil {
		return 0, fmt.Errorf("HMAC context is closed")
	}
	if len(data) == 0 {
		return 0, nil
	}
	if C.X_HMAC_Update(h.ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.size_t(len(data))) != 1 {
		return 0, fmt.Errorf("failed to update HMAC: %w", PopError())
	}
	runtime.KeepAlive(data)
	return len(data), nil
}

func (h *HMAC) Reset() error {
	if h.ctx == nil {
		return fmt.Errorf("HMAC context is closed")
	}
	if C.X_HMAC_Init_ex(h.ctx, nil, 0, nil, nil) != 1 {
		return fmt.Errorf("failed to reset HMAC_CTX: %w", PopError())
	}
	return nil
}

func (h *HMAC) Final() ([]byte, error) {
	if h.ctx == nil {
		return nil, fmt.Errorf("HMAC context is closed")
	}
	var mdLength C.uint = C.uint(C.X_EVP_MD_size(h.md))
	result := make([]byte, mdLength)
	if rc := C.X_HMAC_Final(h.ctx, (*C.uchar)(unsafe.Pointer(&result[0])),
		&mdLength); rc != 1 {
		return nil, fmt.Errorf("failed to final HMAC: %w", PopError())
	}
	return result, h.Reset()
}

// Verify 安全地验证HMAC值，使用常量时间比较
//
// 安全特性：
// - 防止时序攻击
// - 防止长度推断攻击
// - 符合RFC 2104 HMAC规范
//
// 参数：
//
//	expected - 期望的HMAC值
//
// 返回值：
//
//	如果HMAC验证成功返回 nil，否则返回错误
func (h *HMAC) Verify(expected []byte) error {
	// 计算实际的HMAC值（必须始终执行以保持恒定时间）
	actual, err := h.Final()
	if err != nil {
		return err
	}

	// 长度不匹配时仍使用常量时间比较
	// subtle.ConstantTimeCompare 在长度不同时自动返回 false
	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return fmt.Errorf("HMAC verification failed")
	}

	return nil
}
