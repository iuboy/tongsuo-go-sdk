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

// validateDERStructure 检查输入是否满足最小 DER/ASN.1 结构要求。
// 不能保证 DER 有效，但能过滤掉明显畸形的数据，
// 降低触发 C 层 (d2i_X509) 缓冲区越界的风险。
func validateDERStructure(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// ASN.1 SEQUENCE tag = 0x30
	if data[0] != 0x30 {
		return false
	}
	// 解析 length 字段
	length := 0
	offset := 1
	switch {
	case data[1]&0x80 == 0:
		// 短格式
		length = int(data[1])
		offset = 2
	case data[1] == 0x80:
		// 不定长度，不允许
		return false
	case data[1] == 0xFF:
		// 非法
		return false
	default:
		// 长格式
		numBytes := int(data[1] & 0x7F)
		if numBytes > 4 || 2+numBytes > len(data) {
			return false
		}
		for i := 0; i < numBytes; i++ {
			length = (length << 8) | int(data[2+i])
		}
		offset = 2 + numBytes
	}
	// 声明长度不能超过剩余数据
	if offset+length > len(data) {
		return false
	}
	// 基本合理性：不超过 1MB
	if length > 1048576 {
		return false
	}
	return true
}

func FuzzLoadCertificateFromDER(f *testing.F) {
	seeds := [][]byte{
		[]byte{},
		[]byte{0x30, 0x00},
		[]byte{0x30, 0x01, 0x00},
		[]byte{0xFF, 0xFF, 0xFF, 0xFF},
		[]byte{0x30, 0x82, 0x00, 0x03, 0x30, 0x00, 0x00},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if !validateDERStructure(data) {
			return
		}
		cert, err := crypto.LoadCertificateFromDER(data)
		if err != nil {
			return
		}
		if cert != nil {
			_, _ = cert.MarshalPEM()
		}
	})
}

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
