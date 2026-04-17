package crypto

// #include "shim.h"
import "C"
import (
	"fmt"
	"runtime"
	"time"
	"unsafe"
)

// TrustStore wraps X509_STORE for standalone certificate verification.
type TrustStore struct {
	store *C.X509_STORE
}

// NewTrustStore creates a new empty X509 trust store.
func NewTrustStore() (*TrustStore, error) {
	store := C.X509_STORE_new()
	if store == nil {
		return nil, fmt.Errorf("failed to create X509_STORE: %w", PopError())
	}
	ts := &TrustStore{store: store}
	runtime.SetFinalizer(ts, func(ts *TrustStore) {
		C.X509_STORE_free(ts.store)
	})
	return ts, nil
}

// AddCert adds a certificate to the trust store.
func (s *TrustStore) AddCert(cert *Certificate) error {
	if cert == nil || cert.x == nil {
		return ErrNoCert
	}
	if C.X509_STORE_add_cert(s.store, cert.x) != 1 {
		return fmt.Errorf("failed to add cert to trust store: %w", PopError())
	}
	return nil
}

// LoadCertsFromPEM loads all certificates from PEM data into the trust store.
func (s *TrustStore) LoadCertsFromPEM(data []byte) error {
	if len(data) == 0 {
		return ErrNoCert
	}

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&data[0]), C.int(len(data)))
	if bio == nil {
		return ErrMallocFailure
	}
	defer C.BIO_free(bio)

	// Read all certificates from the PEM data
	for {
		cert := C.PEM_read_bio_X509(bio, nil, nil, nil)
		if cert == nil {
			break
		}
		if C.X509_STORE_add_cert(s.store, cert) != 1 {
			C.X509_free(cert)
			return fmt.Errorf("failed to add cert to trust store: %w", PopError())
		}
		C.X509_free(cert)
	}
	return nil
}

// VerifyOptions contains parameters for certificate chain verification.
type VerifyOptions struct {
	// Certificate to verify (required).
	Certificate *Certificate

	// Intermediate certificates for chain building.
	Intermediates []*Certificate

	// Root CA trust store.
	Roots *TrustStore

	// Verification time (zero value means current time).
	CurrentTime time.Time

	// Maximum chain depth (0 = default, which is 100).
	MaxDepth int
}

// VerificationResult contains the result of certificate chain verification.
type VerificationResult struct {
	// Error is nil if verification succeeded.
	Error error

	// Chain contains the verified certificate chain (target to root).
	// Only populated on successful verification.
	Chain []*Certificate

	// ErrorCode is the OpenSSL X509_V_* error code (0 = success).
	ErrorCode int
}

// VerifyCertificate verifies a certificate chain against the given trust store.
//
// It builds a chain from the target certificate through intermediates to a trusted root,
// checking signatures, validity periods, and basic constraints.
func VerifyCertificate(opts *VerifyOptions) (*VerificationResult, error) {
	if opts == nil || opts.Certificate == nil {
		return nil, fmt.Errorf("certificate is required")
	}
	if opts.Roots == nil {
		return nil, fmt.Errorf("trust store (roots) is required")
	}

	// Create verification context
	storeCtx := C.X509_STORE_CTX_new()
	if storeCtx == nil {
		return nil, fmt.Errorf("failed to create X509_STORE_CTX: %w", PopError())
	}
	defer C.X509_STORE_CTX_free(storeCtx)

	// Initialize with trust store and target cert
	if C.X509_STORE_CTX_init(storeCtx, opts.Roots.store, opts.Certificate.x, nil) != 1 {
		return nil, fmt.Errorf("failed to init X509_STORE_CTX: %w", PopError())
	}

	// Set untrusted intermediates.
	//
	// Ownership note: X509_STORE_CTX_set0_untrusted() borrows the stack
	// pointer ("set0" = no refcount increment). X509_STORE_CTX_free()
	// does NOT free the untrusted stack, so we must free it ourselves.
	var untrustedStack *C.struct_stack_st_X509
	if len(opts.Intermediates) > 0 {
		untrustedStack = C.X_sk_X509_new_null()
		if untrustedStack == nil {
			return nil, ErrMallocFailure
		}
		for _, cert := range opts.Intermediates {
			C.X_sk_X509_push(untrustedStack, cert.x)
		}
		C.X_X509_STORE_CTX_set0_untrusted(storeCtx, untrustedStack)
		defer C.X_sk_X509_free(untrustedStack)
	}

	// Set verification parameters
	param := C.X509_STORE_CTX_get0_param(storeCtx)
	if param != nil {
		if !opts.CurrentTime.IsZero() {
			C.X509_VERIFY_PARAM_set_time(param, C.time_t(opts.CurrentTime.Unix()))
		}
		if opts.MaxDepth > 0 {
			C.X509_VERIFY_PARAM_set_depth(param, C.int(opts.MaxDepth))
		}
	}

	// Run verification
	result := C.X509_verify_cert(storeCtx)

	// X509_verify_cert returns: 1=success, 0=verification failed, negative=internal error
	if result < 0 {
		return nil, fmt.Errorf("internal error during certificate verification: %w", PopError())
	}

	if result == 1 {
		// Success: extract chain
		chain := extractChain(storeCtx)
		return &VerificationResult{
			ErrorCode: 0,
			Chain:     chain,
		}, nil
	}

	// Failure
	errorCode := int(C.X509_STORE_CTX_get_error(storeCtx))
	errorDepth := int(C.X509_STORE_CTX_get_error_depth(storeCtx))

	// Get error description
	errStr := C.X509_verify_cert_error_string(C.long(errorCode))
	errDesc := C.GoString(errStr)

	return &VerificationResult{
		ErrorCode: errorCode,
		Error:     fmt.Errorf("certificate verification failed at depth %d: %s", errorDepth, errDesc),
	}, nil
}

// extractChain extracts the verified certificate chain from the store context.
func extractChain(storeCtx *C.X509_STORE_CTX) []*Certificate {
	chain := C.X_X509_STORE_CTX_get0_chain(storeCtx)
	if chain == nil {
		return nil
	}

	num := C.X_sk_X509_num(chain)
	if num <= 0 {
		return nil
	}

	certs := make([]*Certificate, 0, int(num))
	for i := 0; i < int(num); i++ {
		x := C.X_sk_X509_value(chain, C.int(i))
		if x == nil {
			continue
		}
		// Up-ref so the cert survives after storeCtx is freed
		C.X509_up_ref(x)
		cert := &Certificate{x: x}
		runtime.SetFinalizer(cert, func(c *Certificate) {
			C.X509_free(c.x)
		})
		certs = append(certs, cert)
	}
	return certs
}
