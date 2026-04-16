// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

package sm2

// #include "shim.h"
import "C"

import (
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// VerifyASN1 verifies ASN.1 encoded signature. Returns nil on success.
func VerifyASN1(pub crypto.PublicKey, data, sig []byte) error {
	if pub == nil {
		return fmt.Errorf("public key is nil: %w", crypto.ErrNilParameter)
	}
	if pub.KeyType() != crypto.NidSM2 {
		return fmt.Errorf("key type is not sm2: %w", crypto.ErrWrongKeyType)
	}
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty: %w", crypto.ErrNilParameter)
	}
	if len(sig) == 0 {
		return fmt.Errorf("signature cannot be empty: %w", crypto.ErrNilParameter)
	}

	err := pub.VerifyPKCS1v15(crypto.SM3Method(), data, sig)
	if err != nil {
		return fmt.Errorf("failed to verify: %w", err)
	}

	return nil
}

// SignASN1 signs the data with priv and returns ASN.1 encoded signature.
func SignASN1(priv crypto.PrivateKey, data []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("private key is nil: %w", crypto.ErrNilParameter)
	}
	if priv.KeyType() != crypto.NidSM2 {
		return nil, fmt.Errorf("key type is not sm2: %w", crypto.ErrWrongKeyType)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty: %w", crypto.ErrNilParameter)
	}

	ret, err := priv.SignPKCS1v15(crypto.SM3Method(), data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %w", err)
	}

	return ret, nil
}

// Verify verifies the signature in r, s of data using the public key, pub.
// Returns nil on success.
func Verify(pub crypto.PublicKey, data []byte, r, s *big.Int) error {
	if pub == nil {
		return fmt.Errorf("public key is nil: %w", crypto.ErrNilParameter)
	}
	if pub.KeyType() != crypto.NidSM2 {
		return fmt.Errorf("key type is not sm2 %w", crypto.ErrWrongKeyType)
	}
	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty: %w", crypto.ErrNilParameter)
	}
	if r == nil || s == nil {
		return fmt.Errorf("r and s must not be nil: %w", crypto.ErrNilParameter)
	}

	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) == 0 || len(sBytes) == 0 {
		return fmt.Errorf("invalid signature: r or s is zero: %w", crypto.ErrNilParameter)
	}

	sm2Sig := C.ECDSA_SIG_new()
	if sm2Sig == nil {
		return fmt.Errorf("failed to create ECDSA_SIG: %w", crypto.ErrMallocFailure)
	}
	defer C.ECDSA_SIG_free(sm2Sig)

	rBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&rBytes[0])), C.int(len(rBytes)), nil)
	runtime.KeepAlive(rBytes)
	if rBig == nil {
		return fmt.Errorf("failed to create r BIGNUM: %w", crypto.ErrMallocFailure)
	}
	sBig := C.BN_bin2bn((*C.uchar)(unsafe.Pointer(&sBytes[0])), C.int(len(sBytes)), nil)
	runtime.KeepAlive(sBytes)
	if sBig == nil {
		C.BN_free(rBig)
		return fmt.Errorf("failed to create s BIGNUM: %w", crypto.ErrMallocFailure)
	}

	ret := C.ECDSA_SIG_set0(sm2Sig, rBig, sBig)
	if ret != 1 {
		// ECDSA_SIG_set0 takes ownership on success; on failure we must free
		C.BN_free(rBig)
		C.BN_free(sBig)
		return fmt.Errorf("failed to set r/s: %w", crypto.ErrNilParameter)
	}

	len1 := C.i2d_ECDSA_SIG(sm2Sig, nil)

	buf := (*C.uchar)(C.malloc(C.size_t(len1)))
	if buf == nil {
		return fmt.Errorf("failed to allocate signature buffer: %w", crypto.ErrMallocFailure)
	}
	defer C.free(unsafe.Pointer(buf))

	tmp := buf
	len2 := C.i2d_ECDSA_SIG(sm2Sig, &tmp)

	return VerifyASN1(pub, data, C.GoBytes(unsafe.Pointer(buf), len2))
}

// Sign signs the data with the private key, priv.
func Sign(priv crypto.PrivateKey, data []byte) (*big.Int, *big.Int, error) {
	if priv == nil {
		return nil, nil, fmt.Errorf("private key is nil: %w", crypto.ErrNilParameter)
	}
	if priv.KeyType() != crypto.NidSM2 {
		return nil, nil, fmt.Errorf("key type is not sm2: %w", crypto.ErrWrongKeyType)
	}
	if len(data) == 0 {
		return nil, nil, fmt.Errorf("data cannot be empty: %w", crypto.ErrNilParameter)
	}

	sig, err := priv.SignPKCS1v15(crypto.SM3Method(), data)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to sign data: %w", err)
	}

	buf := (*C.uchar)(C.malloc(C.size_t(len(sig))))
	defer C.free(unsafe.Pointer(buf))
	C.memcpy(unsafe.Pointer(buf), unsafe.Pointer(&sig[0]), C.size_t(len(sig)))

	sm2Sig := C.d2i_ECDSA_SIG(nil, &buf, C.long(len(sig)))
	if sm2Sig == nil {
		return nil, nil, fmt.Errorf("failed to decode signature: %w", err)
	}
	defer C.ECDSA_SIG_free(sm2Sig)

	var rBig, sBig *C.BIGNUM
	C.ECDSA_SIG_get0(sm2Sig, &rBig, &sBig)

	rBytes := make([]byte, C.X_BN_num_bytes(rBig))
	sBytes := make([]byte, C.X_BN_num_bytes(sBig))

	rLen := C.BN_bn2bin(rBig, (*C.uchar)(unsafe.Pointer(&rBytes[0])))
	sLen := C.BN_bn2bin(sBig, (*C.uchar)(unsafe.Pointer(&sBytes[0])))

	runtime.KeepAlive(rBytes)
	runtime.KeepAlive(sBytes)

	r := new(big.Int).SetBytes(rBytes[:rLen])
	s := new(big.Int).SetBytes(sBytes[:sLen])

	return r, s, nil
}

// GenerateKey generates a new SM2 key pair.
func GenerateKey() (crypto.PrivateKey, error) {
	priv, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		return nil, fmt.Errorf("failed to create key: %w", err)
	}

	return priv, nil
}

// Encrypt encrypts the data with the public key, publ.
func Encrypt(pub crypto.PublicKey, data []byte) ([]byte, error) {
	if pub.KeyType() != crypto.NidSM2 {
		return nil, fmt.Errorf("key type is not sm2: %w", crypto.ErrWrongKeyType)
	}

	ret, err := pub.Encrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %w", err)
	}

	return ret, nil
}

// Decrypt decrypts the ciphertext with the private key, priv.
func Decrypt(priv crypto.PrivateKey, data []byte) ([]byte, error) {
	if priv.KeyType() != crypto.NidSM2 {
		return nil, fmt.Errorf("key type is not sm2: %w", crypto.ErrWrongKeyType)
	}

	ret, err := priv.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return ret, nil
}
