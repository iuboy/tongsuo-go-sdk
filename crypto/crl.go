package crypto

// #include "shim.h"
import "C"
import (
	"fmt"
	"io"
	"math/big"
	"runtime"
	"time"
	"unsafe"
)

// CertificateRevocationList wraps an OpenSSL X509_CRL object.
type CertificateRevocationList struct {
	crl *C.X509_CRL
}

// RevokedCertificate wraps an OpenSSL X509_REVOKED entry in a CRL.
type RevokedCertificate struct {
	revoked *C.X509_REVOKED
	// added tracks whether this entry has been added to a CRL
	// (ownership transferred to CRL, Go finalizer should not free)
	added bool
}

// NewCertificateRevocationList creates a new v2 CRL.
func NewCertificateRevocationList() (*CertificateRevocationList, error) {
	crl := C.X509_CRL_new()
	if crl == nil {
		return nil, ErrMallocFailure
	}

	if C.X509_CRL_set_version(crl, 1) != 1 { // v2 = 1
		C.X509_CRL_free(crl)
		return nil, fmt.Errorf("failed to set CRL version: %w", PopError())
	}

	c := &CertificateRevocationList{crl: crl}
	runtime.SetFinalizer(c, func(c *CertificateRevocationList) {
		C.X509_CRL_free(c.crl)
	})
	return c, nil
}

// NewRevokedCertificate creates a new CRL revoked entry with the given serial and date.
func NewRevokedCertificate(serial *big.Int, revocationDate time.Time) (*RevokedCertificate, error) {
	if serial == nil || serial.Sign() <= 0 {
		return nil, fmt.Errorf("serial number must be a positive integer")
	}

	rev := C.X509_REVOKED_new()
	if rev == nil {
		return nil, ErrMallocFailure
	}

	rc := &RevokedCertificate{revoked: rev}
	runtime.SetFinalizer(rc, func(r *RevokedCertificate) {
		if !r.added {
			C.X509_REVOKED_free(r.revoked)
		}
	})

	// Set serial number
	serialBytes := serial.Bytes()
	bn := C.BN_new()
	if bn == nil {
		return nil, ErrMallocFailure
	}
	defer C.BN_free(bn)

	if C.BN_bin2bn((*C.uchar)(&serialBytes[0]), C.int(len(serialBytes)), bn) == nil {
		return nil, fmt.Errorf("BN_bin2bn failed: %w", PopError())
	}

	sno := C.ASN1_INTEGER_new()
	if sno == nil {
		return nil, ErrMallocFailure
	}
	defer C.ASN1_INTEGER_free(sno)

	if C.BN_to_ASN1_INTEGER(bn, sno) == nil {
		return nil, fmt.Errorf("BN_to_ASN1_INTEGER failed: %w", PopError())
	}

	if C.X509_REVOKED_set_serialNumber(rev, sno) != 1 {
		return nil, fmt.Errorf("failed to set revoked serial: %w", PopError())
	}

	// Set revocation date
	asn1Time, err := timeToASN1(revocationDate)
	if err != nil {
		return nil, fmt.Errorf("failed to convert revocation date: %w", err)
	}
	defer C.ASN1_STRING_free(asn1Time)

	if C.X509_REVOKED_set_revocationDate(rev, asn1Time) != 1 {
		return nil, fmt.Errorf("failed to set revocation date: %w", PopError())
	}

	return rc, nil
}

// SetIssuerName sets the issuer name of the CRL.
func (c *CertificateRevocationList) SetIssuerName(name *Name) error {
	if C.X509_CRL_set_issuer_name(c.crl, name.name) != 1 {
		return fmt.Errorf("failed to set CRL issuer name: %w", PopError())
	}
	return nil
}

// GetIssuerName returns the issuer name of the CRL.
func (c *CertificateRevocationList) GetIssuerName() (*Name, error) {
	n := C.X509_CRL_get_issuer(c.crl)
	if n == nil {
		return nil, fmt.Errorf("failed to get CRL issuer name")
	}
	return &Name{name: n}, nil
}

// SetLastUpdate sets the thisUpdate field of the CRL.
func (c *CertificateRevocationList) SetLastUpdate(t time.Time) error {
	asn1Time, err := timeToASN1(t)
	if err != nil {
		return err
	}
	// set1 makes a copy, so we free our local copy
	defer C.ASN1_STRING_free(asn1Time)
	if C.X509_CRL_set1_lastUpdate(c.crl, asn1Time) != 1 {
		return fmt.Errorf("failed to set CRL lastUpdate: %w", PopError())
	}
	return nil
}

// SetNextUpdate sets the nextUpdate field of the CRL.
func (c *CertificateRevocationList) SetNextUpdate(t time.Time) error {
	asn1Time, err := timeToASN1(t)
	if err != nil {
		return err
	}
	defer C.ASN1_STRING_free(asn1Time)
	if C.X509_CRL_set1_nextUpdate(c.crl, asn1Time) != 1 {
		return fmt.Errorf("failed to set CRL nextUpdate: %w", PopError())
	}
	return nil
}

// AddRevokedCertificate adds a revoked entry to the CRL.
// After this call, the RevokedCertificate ownership transfers to the CRL.
func (c *CertificateRevocationList) AddRevokedCertificate(rc *RevokedCertificate) error {
	if C.X_X509_CRL_add0_revoked(c.crl, rc.revoked) != 1 {
		return fmt.Errorf("failed to add revoked certificate to CRL: %w", PopError())
	}
	// CRL takes ownership, clear Go finalizer
	rc.added = true
	runtime.SetFinalizer(rc, nil)
	return nil
}

// Sign signs the CRL with the given private key and digest algorithm.
func (c *CertificateRevocationList) Sign(privKey PrivateKey, digest DigestAlgo) error {
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

	if C.X509_CRL_sign(c.crl, privKey.EvpPKey(), md) <= 0 {
		return fmt.Errorf("failed to sign CRL: %w", PopError())
	}
	return nil
}

// signSM2 signs the CRL using SM2 with EVP_MD_CTX.
func (c *CertificateRevocationList) signSM2(privKey PrivateKey, md *C.EVP_MD) error {
	return signWithSM2MD(privKey, md, func(ctx *C.EVP_MD_CTX) C.int {
		return C.X_X509_CRL_sign_ctx(c.crl, ctx)
	})
}

// GetRevokedCertificates returns all revoked entries in the CRL.
//
// WARNING: The returned RevokedCertificate objects borrow pointers from the
// CRL's internal storage. Their lifetime is bound to the parent CRL. Callers
// must not use the returned entries after the CRL is garbage-collected or freed.
func (c *CertificateRevocationList) GetRevokedCertificates() ([]*RevokedCertificate, error) {
	sk := C.X509_CRL_get_REVOKED(c.crl)
	if sk == nil {
		return nil, nil
	}

	num := C.X_sk_X509_REVOKED_num(sk)
	if num <= 0 {
		return nil, nil
	}

	result := make([]*RevokedCertificate, 0, int(num))
	for i := 0; i < int(num); i++ {
		entry := C.X_sk_X509_REVOKED_value(sk, C.int(i))
		if entry == nil {
			continue
		}
		result = append(result, &RevokedCertificate{revoked: entry, added: true})
	}
	return result, nil
}

// GetSerialNumber returns the serial number of the revoked entry.
func (rc *RevokedCertificate) GetSerialNumber() *big.Int {
	asn1Num := C.X509_REVOKED_get0_serialNumber(rc.revoked)
	if asn1Num == nil {
		return nil
	}
	bignum := C.ASN1_INTEGER_to_BN(asn1Num, nil)
	if bignum == nil {
		return nil
	}
	defer C.BN_free(bignum)

	// BN_num_bytes gives the byte length of the absolute value
	bufLen := C.X_BN_num_bytes(bignum)
	if bufLen <= 0 {
		return big.NewInt(0)
	}
	buf := make([]byte, int(bufLen))
	C.X_BN_bn2bin(bignum, (*C.uchar)(&buf[0]))

	return new(big.Int).SetBytes(buf)
}

// GetRevocationDate returns the revocation date of the entry.
func (rc *RevokedCertificate) GetRevocationDate() (time.Time, error) {
	date := C.X509_REVOKED_get0_revocationDate(rc.revoked)
	if date == nil {
		return time.Time{}, fmt.Errorf("no revocation date")
	}
	return asn1ToTime(date)
}

// MarshalPEM converts the CRL to PEM-encoded format.
func (c *CertificateRevocationList) MarshalPEM() ([]byte, error) {
	bio := C.BIO_new(C.BIO_s_mem())
	if bio == nil {
		return nil, ErrMallocFailure
	}
	defer C.BIO_free(bio)

	if C.PEM_write_bio_X509_CRL(bio, c.crl) != 1 {
		return nil, fmt.Errorf("failed to write CRL: %w", PopError())
	}

	return io.ReadAll(asAnyBio(bio))
}

// MarshalDER converts the CRL to DER-encoded format.
func (c *CertificateRevocationList) MarshalDER() ([]byte, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	var buf *C.uchar
	length := C.i2d_X509_CRL(c.crl, &buf)
	if length <= 0 {
		return nil, fmt.Errorf("failed to serialize CRL to DER: %w", PopError())
	}
	defer C.X_OPENSSL_free(unsafe.Pointer(buf))

	return C.GoBytes(unsafe.Pointer(buf), C.int(length)), nil
}

// LoadCRLFromPEM loads a CRL from PEM-encoded bytes.
func LoadCRLFromPEM(pemBlock []byte) (*CertificateRevocationList, error) {
	if len(pemBlock) == 0 {
		return nil, ErrNoCRL
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	bio := C.BIO_new_mem_buf(unsafe.Pointer(&pemBlock[0]), C.int(len(pemBlock)))
	crl := C.PEM_read_bio_X509_CRL(bio, nil, nil, nil)
	C.BIO_free(bio)
	if crl == nil {
		return nil, fmt.Errorf("failed to parse CRL from PEM: %w", PopError())
	}

	c := &CertificateRevocationList{crl: crl}
	runtime.SetFinalizer(c, func(c *CertificateRevocationList) {
		C.X509_CRL_free(c.crl)
	})
	return c, nil
}

// LoadCRLFromDER loads a CRL from DER-encoded bytes.
func LoadCRLFromDER(derBytes []byte) (*CertificateRevocationList, error) {
	if len(derBytes) == 0 {
		return nil, ErrNoCRL
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Copy to C memory to avoid Go 1.26 cgo pointer check
	cBuf := C.CBytes(derBytes)
	defer C.X_free(cBuf)

	p := (*C.uchar)(cBuf)
	crl := C.d2i_X509_CRL(nil, &p, C.long(len(derBytes)))
	if crl == nil {
		return nil, fmt.Errorf("failed to parse CRL from DER: %w", PopError())
	}

	c := &CertificateRevocationList{crl: crl}
	runtime.SetFinalizer(c, func(c *CertificateRevocationList) {
		C.X509_CRL_free(c.crl)
	})
	return c, nil
}
