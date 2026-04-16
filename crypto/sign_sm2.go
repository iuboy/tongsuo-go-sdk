package crypto

// #include "shim.h"
import "C"
import (
	"fmt"
	"unsafe"
)

// defaultSM2ID is the default SM2 user ID ("1234567812345678") per GM/T 0009-2012.
// Pre-computed at init time to avoid per-call allocation.
var defaultSM2ID []byte

// defaultSM2IDPtr is the C copy of the default SM2 ID.
var defaultSM2IDPtr unsafe.Pointer

func init() {
	defaultSM2ID = []byte("1234567812345678")
	defaultSM2IDPtr = C.CBytes(defaultSM2ID)
}

// signWithSM2MD 使用 SM2 EVP_MD_CTX 路径签名。
//
// SM2 签名必须通过 EVP_MD_CTX 设置用户 ID（默认 "1234567812345678"），
// 而不能直接使用 X509_sign / X509_REQ_sign / X509_CRL_sign。
//
// signFunc 接收初始化好的 EVP_MD_CTX，执行实际的 sign_ctx 调用。
// 返回值: 1=成功, <=0=失败。
func signWithSM2MD(privKey PrivateKey, md *C.EVP_MD, signFunc func(*C.EVP_MD_CTX) C.int) error {
	ctx := C.X_EVP_MD_CTX_new()
	if ctx == nil {
		return fmt.Errorf("failed to create MD_CTX: %w", PopError())
	}
	defer C.X_EVP_MD_CTX_free(ctx)

	var pctx *C.EVP_PKEY_CTX
	if C.X_EVP_DigestSignInit(ctx, &pctx, md, nil, privKey.EvpPKey()) <= 0 {
		return fmt.Errorf("failed to init SM2 sign: %w", PopError())
	}

	if C.X_EVP_PKEY_CTX_set1_id(pctx, defaultSM2IDPtr, C.int(len(defaultSM2ID))) <= 0 {
		return fmt.Errorf("failed to set SM2 ID: %w", PopError())
	}

	if signFunc(ctx) <= 0 {
		return fmt.Errorf("failed to sign with SM2: %w", PopError())
	}

	return nil
}
