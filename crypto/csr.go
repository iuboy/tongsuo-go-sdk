package crypto

// #include "shim.h"
import "C"
import (
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

// CertificateSigningRequest wraps an OpenSSL X509_REQ object.
type CertificateSigningRequest struct {
	req    *C.X509_REQ
	pubKey PublicKey
}

// NewCertificateSigningRequest creates a new PKCS#10 v1 CSR.
func NewCertificateSigningRequest(pubKey PublicKey) (*CertificateSigningRequest, error) {
	req := C.X509_REQ_new()
	if req == nil {
		return nil, ErrMallocFailure
	}

	if C.X509_REQ_set_version(req, 0) != 1 {
		C.X509_REQ_free(req)
		return nil, fmt.Errorf("failed to set CSR version: %w", PopError())
	}

	if C.X509_REQ_set_pubkey(req, pubKey.EvpPKey()) != 1 {
		C.X509_REQ_free(req)
		return nil, fmt.Errorf("failed to set CSR public key: %w", PopError())
	}

	csr := &CertificateSigningRequest{req: req, pubKey: pubKey}
	runtime.SetFinalizer(csr, func(c *CertificateSigningRequest) {
		C.X509_REQ_free(c.req)
	})

	return csr, nil
}

// SetSubjectName sets the subject name of the CSR.
func (c *CertificateSigningRequest) SetSubjectName(name *Name) error {
	if C.X509_REQ_set_subject_name(c.req, name.name) != 1 {
		return fmt.Errorf("failed to set CSR subject name: %w", PopError())
	}
	return nil
}

// GetSubjectName returns the subject name of the CSR.
func (c *CertificateSigningRequest) GetSubjectName() (*Name, error) {
	n := C.X509_REQ_get_subject_name(c.req)
	if n == nil {
		return nil, fmt.Errorf("failed to get CSR subject name")
	}
	return &Name{name: n}, nil
}

// Sign signs the CSR with the given private key and digest algorithm.
// For SM2 keys, uses EVP_MD_CTX path with SM2 ID.
func (c *CertificateSigningRequest) Sign(privKey PrivateKey, digest DigestAlgo) error {
	switch digest {
	case DigestSM3, DigestSHA256, DigestSHA384, DigestSHA512:
	default:
		return ErrUnsupportedDigest
	}

	md := getDigestFunction(digest)
	if md == nil {
		return ErrUnsupportedDigest
	}

	if privKey.KeyType() == KeyTypeSM2 {
		return c.signSM2(privKey, md)
	}

	if C.X509_REQ_sign(c.req, privKey.EvpPKey(), md) <= 0 {
		return fmt.Errorf("failed to sign CSR: %w", PopError())
	}
	return nil
}

// signSM2 signs the CSR using SM2 with EVP_MD_CTX for SM2 ID handling.
func (c *CertificateSigningRequest) signSM2(privKey PrivateKey, md *C.EVP_MD) error {
	return signWithSM2MD(privKey, md, func(ctx *C.EVP_MD_CTX) C.int {
		return C.X_X509_REQ_sign_ctx(c.req, ctx)
	})
}

// AddExtension adds an X509v3 extension to the CSR.
func (c *CertificateSigningRequest) AddExtension(nid NID, value string) error {
	if nid <= 0 {
		return ErrInvalidNid
	}
	if value == "" {
		return ErrEmptyExtensionValue
	}

	cValue := C.CString(value)
	defer C.free(unsafe.Pointer(cValue))

	if C.X_X509_REQ_add1_ext(c.req, C.int(nid), cValue) != 1 {
		return fmt.Errorf("failed to add CSR extension: %w", PopError())
	}
	return nil
}

// GetPublicKey extracts the public key from the CSR.
func (c *CertificateSigningRequest) GetPublicKey() (PublicKey, error) {
	pkey := C.X509_REQ_get_pubkey(c.req)
	if pkey == nil {
		return nil, ErrNoPubKey
	}
	key := &pKey{key: pkey}
	runtime.SetFinalizer(key, func(k *pKey) {
		C.EVP_PKEY_free(k.key)
	})
	return key, nil
}

// MarshalPEM converts the CSR to PEM-encoded format.
func (c *CertificateSigningRequest) MarshalPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if C.PEM_write_bio_X509_REQ(bio, c.req) != 1 {
		return nil, fmt.Errorf("failed to write CSR: %w", PopError())
	}

	return io.ReadAll(asAnyBio(bio))
}

// MarshalDER converts the CSR to DER-encoded format.
func (c *CertificateSigningRequest) MarshalDER() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var buf *C.uchar
	length := C.i2d_X509_REQ(c.req, &buf)
	if length <= 0 {
		return nil, fmt.Errorf("failed to serialize CSR to DER: %w", PopError())
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(buf))

	return C.GoBytes(unsafe.Pointer(buf), C.int(length)), nil
}

// LoadCSRFromPEM loads a CSR from PEM-encoded bytes.
func LoadCSRFromPEM(pemBlock []byte) (*CertificateSigningRequest, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCSR
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]), C.int(len(pemBlock)))
	req := C.PEM_read_bio_X509_REQ(bio, nil, nil, nil)
	C.BIO_free(bio)
	if req == nil {
		return nil, fmt.Errorf("failed to parse CSR from PEM: %w", PopError())
	}

	csr := &CertificateSigningRequest{req: req}
	runtime.SetFinalizer(csr, func(c *CertificateSigningRequest) {
		C.X509_REQ_free(c.req)
	})
	return csr, nil
}

// LoadCSRFromDER loads a CSR from DER-encoded bytes.
func LoadCSRFromDER(derBytes []byte) (*CertificateSigningRequest, error) {
	if len(derBytes) == 0 {
		return nil, ErrNoCSR
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Copy to C memory to avoid Go 1.26 cgo pointer check
	cBuf := C.CBytes(derBytes)
	defer C.X_free(cBuf)

	p := (*C.uchar)(cBuf)
	req := C.d2i_X509_REQ(nil, &p, C.long(len(derBytes)))
	if req == nil {
		return nil, fmt.Errorf("failed to parse CSR from DER: %w", PopError())
	}

	csr := &CertificateSigningRequest{req: req}
	runtime.SetFinalizer(csr, func(c *CertificateSigningRequest) {
		C.X509_REQ_free(c.req)
	})
	return csr, nil
}
