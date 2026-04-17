// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package crypto

// #include "shim.h"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
)

var (
	ErrMallocFailure       = errors.New("malloc failure")
	ErrNilParameter        = errors.New("nil parameter")
	ErrNoCipher            = errors.New("no cipher")
	ErrNoVersion           = errors.New("no version")
	ErrUnexpectedEOF       = errors.New("unexpected EOF")
	ErrNoPeerCert          = errors.New("no peer certificate")
	ErrShutdown            = errors.New("shutdown")
	ErrNoSession           = errors.New("no session")
	ErrSessionLength       = errors.New("session length error")
	ErrEmptySession        = errors.New("empty session")
	ErrNoALPN              = errors.New("no ALPN negotiated")
	ErrWrongKeyType        = errors.New("wrong key type")
	ErrUnknownTLSVersion   = errors.New("unknown TLS version")
	ErrNoCert              = errors.New("no certificate")
	ErrNoKey               = errors.New("no key")
	ErrUnsupportedMode     = errors.New("unsupported cipher mode")
	ErrPartialWrite        = errors.New("partial write")
	ErrUnsupportedDigest   = errors.New("unsupported digest")
	ErrInvalidNid          = errors.New("invalid NID")
	ErrEmptyExtensionValue = errors.New("empty extension value")
	ErrNoPubKey            = errors.New("no public key")
	ErrCipherNotFound      = errors.New("cipher not found")
	ErrBadKeySize          = errors.New("bad key size")
	ErrBadIvSize           = errors.New("bad IV size")
	ErrUknownBlockSize     = errors.New("unknown block size")
	ErrMatchFailed         = errors.New("match failed")
	ErrInputInvalid        = errors.New("input invalid")
	ErrInternalError       = errors.New("internal error")
	ErrEmptyKey            = errors.New("empty key")
	ErrNoData              = errors.New("no data")
	ErrInvalidKeySize      = errors.New("invalid key size")
	ErrDecryptionFailed    = errors.New("decryption failed")
	ErrOCSPResponseCreate  = errors.New("OCSP response create failed")
	ErrOCSPResponseParse   = errors.New("OCSP response parse failed")
	ErrOCSPStatusNotFound  = errors.New("OCSP status not found for certificate")
	ErrNoCSR               = errors.New("no certificate signing request")
	ErrNoCRL               = errors.New("no certificate revocation list")
)

// 安全模式配置
// 通过环境变量 TONGSUO_DETAILED_ERRORS=true 启用详细错误信息
// 生产环境应该禁用详细错误以防止信息泄露
// 使用 atomic.Bool 保证并发读写的线程安全
var detailedErrors atomic.Bool

// setDetailedErrorsOnce 确保 SetDetailedErrors 只执行一次
var setDetailedErrorsOnce sync.Once

func init() {
	detailedErrors.Store(os.Getenv("TONGSUO_DETAILED_ERRORS") == "true")
	// 环境变量初始化后锁定设置，防止运行时修改
	// 如果需要运行时通过 SetDetailedErrors 修改，必须在第一次调用前完成
}

func init() {
	if rc := C.X_tscrypto_init(); rc != 0 {
		panic(fmt.Sprintf("X_tscrypto_init failed with %d", rc))
	}
}

// PopError 获取并返回OpenSSL/Tongsuo错误堆栈中的错误信息
//
// 安全特性：
// - 在生产环境（detailedErrors=false）返回通用错误消息
// - 在开发环境（detailedErrors=true）返回详细错误信息
// - 防止通过错误消息泄露敏感实现细节
//
// 注意：此函数必须在导致错误的同一OS线程中调用
func PopError() error {
	// 根据环境变量决定错误详细程度
	if detailedErrors.Load() {
		// 开发环境：收集并返回详细错误信息
		var errs []string

		for {
			err := C.ERR_get_error()
			if err == 0 {
				break
			}
			errs = append(errs, fmt.Sprintf("%s:%s:%s",
				C.GoString(C.ERR_lib_error_string(err)),
				C.GoString(C.ERR_func_error_string(err)),
				C.GoString(C.ERR_reason_error_string(err))))
		}

		if len(errs) == 0 {
			return errors.New("cryptographic operation failed (unknown error)")
		}
		return errors.New("error string: " + strings.Join(errs, "\n"))
	}

	// 生产环境：只清空错误队列，不收集敏感字符串
	// 避免通过 C.GoString 分配和保留 OpenSSL 内部函数名、库名等信息
	hasErrors := false
	for {
		err := C.ERR_get_error()
		if err == 0 {
			break
		}
		hasErrors = true
	}

	if !hasErrors {
		return errors.New("cryptographic operation failed")
	}

	return errors.New("cryptographic operation failed")
}

// SetDetailedErrors 设置是否返回详细错误信息
//
// 此函数只能调用一次。第一次调用后设置被锁定，后续调用会被忽略。
// 这防止攻击者在运行时切换详细错误模式以泄露敏感信息。
//
// 安全警告：
// - 仅在开发/调试环境启用详细错误
// - 生产环境必须保持禁用状态
// - 启用后可能泄露敏感实现信息
func SetDetailedErrors(enabled bool) {
	setDetailedErrorsOnce.Do(func() {
		detailedErrors.Store(enabled)
	})
}

// IsDetailedErrorsEnabled 返回当前是否启用了详细错误
func IsDetailedErrorsEnabled() bool {
	return detailedErrors.Load()
}
