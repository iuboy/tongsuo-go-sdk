// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm3

// #include "shim.h"
import "C"

import (
	"fmt"
	"hash"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	MDSize    = 32
	sm3Cblock = 64
)

var _ hash.Hash = new(SM3)

type SM3 struct {
	ctx *C.EVP_MD_CTX
	err error
}

func New() (*SM3, error) {
	hash := &SM3{ctx: nil}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		return nil, fmt.Errorf("failed to create md ctx: %w", crypto.ErrMallocFailure)
	}
	runtime.SetFinalizer(hash, func(hash *SM3) { hash.Close() })
	hash.Reset()
	if hash.err != nil {
		return nil, hash.err
	}

	return hash, nil
}

func (s *SM3) BlockSize() int {
	return sm3Cblock
}

func (s *SM3) Size() int {
	return MDSize
}

func (s *SM3) Close() {
	if s.ctx != nil {
		C.X_EVP_MD_CTX_free(s.ctx)
		s.ctx = nil
	}
}

func (s *SM3) Reset() {
	s.err = nil
	if s.ctx == nil {
		s.err = fmt.Errorf("sm3: context is nil: %w", crypto.ErrNilParameter)
		return
	}
	if C.X_EVP_DigestInit_ex(s.ctx, C.EVP_sm3(), nil) != 1 {
		s.err = fmt.Errorf("sm3: digest init failed: %w", crypto.PopError())
	}
}

func (s *SM3) Write(data []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	if len(data) == 0 {
		return 0, nil
	}
	if s.ctx == nil {
		return 0, fmt.Errorf("sm3: context is nil: %w", crypto.ErrNilParameter)
	}
	if C.X_EVP_DigestUpdate(s.ctx, unsafe.Pointer(&data[0]), C.size_t(len(data))) != 1 {
		s.err = fmt.Errorf("failed to update digest: %w", crypto.PopError())
		return 0, s.err
	}
	return len(data), nil
}

func (s *SM3) Sum(in []byte) []byte {
	if s.err != nil {
		panic("sm3: cipher operation failed")
	}
	hash := &SM3{ctx: nil}
	hash.ctx = C.X_EVP_MD_CTX_new()
	if hash.ctx == nil {
		panic("sm3: cipher operation failed")
	}
	runtime.SetFinalizer(hash, func(hash *SM3) { hash.Close() })

	if C.X_EVP_MD_CTX_copy_ex(hash.ctx, s.ctx) == 0 {
		panic("sm3: cipher operation failed")
	}

	result := hash.checkSum()
	return append(in, result[:]...)
}

func (s *SM3) checkSum() [MDSize]byte {
	var result [MDSize]byte

	C.X_EVP_DigestFinal_ex(s.ctx, (*C.uchar)(unsafe.Pointer(&result[0])), nil)

	return result
}

// Sum computes the SM3 hash of data in a single call.
// Returns an error if the underlying OpenSSL operation fails.
func Sum(data []byte) ([MDSize]byte, error) {
	var result [MDSize]byte

	if len(data) == 0 {
		if C.X_EVP_Digest(nil, 0, (*C.uchar)(unsafe.Pointer(&result[0])), nil,
			C.EVP_sm3(), nil) != 1 {
			return result, fmt.Errorf("sm3: digest failed: %w", crypto.PopError())
		}
		return result, nil
	}

	if C.X_EVP_Digest(unsafe.Pointer(&data[0]), C.size_t(len(data)), (*C.uchar)(unsafe.Pointer(&result[0])), nil,
		C.EVP_sm3(), nil) != 1 {
		return result, fmt.Errorf("sm3: digest failed: %w", crypto.PopError())
	}

	return result, nil
}
