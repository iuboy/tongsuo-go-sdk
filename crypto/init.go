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
)

// 安全模式配置
// 通过环境变量 TONGSUO_DETAILED_ERRORS=1 启用详细错误信息
// 生产环境应该禁用详细错误以防止信息泄露
var detailedErrors = os.Getenv("TONGSUO_DETAILED_ERRORS") == "true"

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
	var errs []string

	// 收集所有错误信息用于日志记录（即使在生产环境）
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

	// 根据环境变量决定返回的错误详细程度
	if detailedErrors {
		// 开发环境：返回详细错误信息
		if len(errs) == 0 {
			return errors.New("cryptographic operation failed (unknown error)")
		}
		return errors.New("error string: " + strings.Join(errs, "\n"))
	}

	// 生产环境：返回通用错误消息
	// 这防止了以下信息泄露：
	// 1. 内部函数名和实现细节
	// 2. 内存布局信息
	// 3. 版本探测信息
	// 4. 潜在的漏洞利用路径
	if len(errs) == 0 {
		return errors.New("cryptographic operation failed")
	}

	// 在生产环境，可以记录详细错误到日志系统
	// 但只向调用者返回通用错误
	// logDetailedError(errs) // 建议调用者实现自己的日志记录

	return errors.New("cryptographic operation failed")
}

// collectErrors 内部函数：收集所有OpenSSL错误用于日志记录
//
// 此函数用于将详细错误信息记录到安全日志系统，
// 供安全团队分析，但不向用户暴露。
func collectErrors() []string {
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
	return errs
}

// SetDetailedErrors 设置是否返回详细错误信息
//
// 安全警告：
// - 仅在开发/调试环境启用详细错误
// - 生产环境必须保持禁用状态
// - 启用后可能泄露敏感实现信息
func SetDetailedErrors(enabled bool) {
	detailedErrors = enabled
}

// IsDetailedErrorsEnabled 返回当前是否启用了详细错误
func IsDetailedErrorsEnabled() bool {
	return detailedErrors
}
