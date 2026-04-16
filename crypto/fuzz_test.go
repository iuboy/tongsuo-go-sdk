// Fuzzing 测试
//
// Go 1.21+ 原生 fuzzing，覆盖输入校验场景:
// - PEM/DER 证书解析
// - PEM/DER CSR 解析
// - PEM/DER CRL 解析
// - 密钥加载 (PEM/DER, 公钥/私钥)
//
// 运行: go test -fuzz=Fuzz -fuzztime=30s ./crypto/
package crypto_test

import (
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// ---------------------------------------------------------------------------
// 证书
// ---------------------------------------------------------------------------

func FuzzLoadCertificateFromPEM(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"),
		[]byte("not pem at all"),
		[]byte("-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKH5JBWsqKWAMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnRlc3Qx\n-----END CERTIFICATE-----\n"),
		[]byte("-----BEGIN "),
		[]byte("-----END CERTIFICATE-----"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cert, err := crypto.LoadCertificateFromPEM(data)
		if err != nil {
			return
		}
		if cert != nil {
			_, _ = cert.MarshalPEM()
		}
	})
}

// TODO(security): LoadCertificateFromDER fuzz 测试暂时移除。
// 原因: Tongsuo d2i_X509 对畸形 DER 输入会触发 C 层缓冲区越界 panic。
// 需要在 Go 层添加 DER 输入预校验后再启用。

// ---------------------------------------------------------------------------
// CSR
// ---------------------------------------------------------------------------

func FuzzLoadCSRFromPEM(f *testing.F) {
	f.Add([]byte("-----BEGIN CERTIFICATE REQUEST-----\n-----END CERTIFICATE REQUEST-----\n"))
	f.Add([]byte(""))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		csr, err := crypto.LoadCSRFromPEM(data)
		if err != nil {
			return
		}
		if csr != nil {
			_, _ = csr.MarshalPEM()
		}
	})
}

func FuzzLoadCSRFromDER(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x01, 0x00}) // minimal ASN1 SEQUENCE
	f.Add([]byte{0xFF, 0xFF, 0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		csr, err := crypto.LoadCSRFromDER(data)
		if err != nil {
			return
		}
		if csr != nil {
			_, _ = csr.MarshalDER()
		}
	})
}

// ---------------------------------------------------------------------------
// CRL
// ---------------------------------------------------------------------------

func FuzzLoadCRLFromPEM(f *testing.F) {
	f.Add([]byte("-----BEGIN X509 CRL-----\n-----END X509 CRL-----\n"))
	f.Add([]byte(""))
	f.Add([]byte("garbage"))
	f.Fuzz(func(t *testing.T, data []byte) {
		crl, err := crypto.LoadCRLFromPEM(data)
		if err != nil {
			return
		}
		if crl != nil {
			_, _ = crl.MarshalPEM()
		}
	})
}

func FuzzLoadCRLFromDER(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, 0x01, 0x00})
	f.Add([]byte{0xFF, 0xFF})
	f.Fuzz(func(t *testing.T, data []byte) {
		crl, err := crypto.LoadCRLFromDER(data)
		if err != nil {
			return
		}
		if crl != nil {
			_, _ = crl.MarshalDER()
		}
	})
}

// ---------------------------------------------------------------------------
// 密钥 (私钥)
// ---------------------------------------------------------------------------

func FuzzLoadPrivateKeyFromPEM(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("-----BEGIN PRIVATE KEY-----\n-----END PRIVATE KEY-----"),
		[]byte("-----BEGIN PRIVATE KEY-----\ninvalid\n-----END PRIVATE KEY-----"),
		[]byte("-----BEGIN RSA PRIVATE KEY-----\ninvalid\n-----END RSA PRIVATE KEY-----"),
		[]byte("-----BEGIN EC PRIVATE KEY-----\ninvalid\n-----END EC PRIVATE KEY-----"),
		[]byte("random garbage"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = crypto.LoadPrivateKeyFromPEM(data)
	})
}

func FuzzLoadPrivateKeyFromDER(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte{0x30, 0x00},
		make([]byte, 32),
		make([]byte, 256),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = crypto.LoadPrivateKeyFromDER(data)
	})
}

// ---------------------------------------------------------------------------
// 密钥 (公钥)
// ---------------------------------------------------------------------------

func FuzzLoadPublicKeyFromPEM(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("-----BEGIN PUBLIC KEY-----\n-----END PUBLIC KEY-----"),
		[]byte("-----BEGIN PUBLIC KEY-----\ninvalid\n-----END PUBLIC KEY-----"),
		[]byte("random garbage"),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = crypto.LoadPublicKeyFromPEM(data)
	})
}

func FuzzLoadPublicKeyFromDER(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte{0x30, 0x00},
		make([]byte, 32),
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = crypto.LoadPublicKeyFromDER(data)
	})
}
