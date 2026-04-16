package crypto_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

// createTestCAChain creates a 3-level certificate chain: root → intermediate → leaf
func createTestCAChain(t *testing.T) (root *crypto.Certificate, rootKey crypto.PrivateKey,
	intermediate *crypto.Certificate, intermediateKey crypto.PrivateKey,
	leaf *crypto.Certificate, leafKey crypto.PrivateKey) {

	t.Helper()

	// Root CA
	rootKey, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	rootInfo := &crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       0,
		Expires:      365 * 24 * time.Hour,
		Country:      "CN",
		Organization: "Test Root CA",
		CommonName:   "Test Root CA",
	}
	root, err = crypto.NewCertificate(rootInfo, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE")
	root.AddExtension(crypto.NidKeyUsage, "critical,keyCertSign,cRLSign")
	if err := root.Sign(rootKey, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	// Intermediate CA
	intermediateKey, err = crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	interInfo := &crypto.CertificateInfo{
		Serial:       big.NewInt(2),
		Issued:       0,
		Expires:      365 * 24 * time.Hour,
		Country:      "CN",
		Organization: "Test Intermediate CA",
		CommonName:   "Test Intermediate CA",
	}
	intermediate, err = crypto.NewCertificate(interInfo, intermediateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := intermediate.SetIssuer(root); err != nil {
		t.Fatal(err)
	}
	intermediate.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE")
	intermediate.AddExtension(crypto.NidKeyUsage, "critical,keyCertSign")
	if err := intermediate.Sign(rootKey, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	// Leaf cert
	leafKey, err = crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	leafInfo := &crypto.CertificateInfo{
		Serial:       big.NewInt(3),
		Issued:       0,
		Expires:      365 * 24 * time.Hour,
		Country:      "CN",
		Organization: "Test Leaf",
		CommonName:   "test.example.com",
	}
	leaf, err = crypto.NewCertificate(leafInfo, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := leaf.SetIssuer(intermediate); err != nil {
		t.Fatal(err)
	}
	leaf.AddExtension(crypto.NidBasicConstraints, "critical,CA:FALSE")
	leaf.AddExtension(crypto.NidKeyUsage, "digitalSignature,keyEncipherment")
	if err := leaf.Sign(intermediateKey, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	return
}

// createTestCAChainSM2 creates a 3-level SM2+SM3 certificate chain
func createTestCAChainSM2(t *testing.T) (root *crypto.Certificate, rootKey crypto.PrivateKey,
	intermediate *crypto.Certificate, intermediateKey crypto.PrivateKey,
	leaf *crypto.Certificate, leafKey crypto.PrivateKey) {

	t.Helper()

	// Root CA (SM2)
	rootKey, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootInfo := &crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       0,
		Expires:      365 * 24 * time.Hour,
		Country:      "CN",
		Organization: "SM2 Root CA",
		CommonName:   "SM2 Root CA",
	}
		root, err = crypto.NewCertificate(rootInfo, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := root.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE"); err != nil {
			t.Fatal(err)
		}
		if err := root.AddExtension(crypto.NidKeyUsage, "critical,keyCertSign,cRLSign"); err != nil {
			t.Fatal(err)
		}
		if err := root.Sign(rootKey, crypto.DigestSM3); err != nil {
			t.Fatal(err)
		}

		// Intermediate CA (SM2)
		intermediateKey, err = sm2.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		interInfo := &crypto.CertificateInfo{
			Serial:       big.NewInt(2),
			Issued:       0,
			Expires:      365 * 24 * time.Hour,
			Country:      "CN",
			Organization: "SM2 Intermediate CA",
			CommonName:   "SM2 Intermediate CA",
		}
		intermediate, err = crypto.NewCertificate(interInfo, intermediateKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := intermediate.SetIssuer(root); err != nil {
			t.Fatal(err)
		}
		if err := intermediate.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE"); err != nil {
			t.Fatal(err)
		}
		if err := intermediate.Sign(rootKey, crypto.DigestSM3); err != nil {
			t.Fatal(err)
		}

		// Leaf (SM2)
		leafKey, err = sm2.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		leafInfo := &crypto.CertificateInfo{
			Serial:       big.NewInt(3),
			Issued:       0,
			Expires:      365 * 24 * time.Hour,
			Country:      "CN",
			Organization: "SM2 Leaf",
			CommonName:   "sm2.example.com",
		}
		leaf, err = crypto.NewCertificate(leafInfo, leafKey)
		if err != nil {
			t.Fatal(err)
		}
		if err := leaf.SetIssuer(intermediate); err != nil {
			t.Fatal(err)
		}
		if err := leaf.AddExtension(crypto.NidBasicConstraints, "critical,CA:FALSE"); err != nil {
			t.Fatal(err)
		}
		if err := leaf.Sign(intermediateKey, crypto.DigestSM3); err != nil {
			t.Fatal(err)
		}

		return
}

func TestVerify_ValidChain(t *testing.T) {
	t.Parallel()

	root, rootKey, intermediate, _, leaf, _ := createTestCAChain(t)

	store, err := crypto.NewTrustStore()
	if err != nil {
		t.Fatal(err)
	}
	store.AddCert(root)

	result, err := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate:   leaf,
		Intermediates: []*crypto.Certificate{intermediate},
		Roots:         store,
	})
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("verification failed: %v (code=%d)", result.Error, result.ErrorCode)
	}
	if len(result.Chain) < 2 {
		t.Errorf("chain length = %d, want >= 2", len(result.Chain))
	}

	// Verify root can verify itself
	selfResult, _ := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: root,
		Roots:       store,
	})
	if selfResult.Error != nil {
		t.Errorf("root self-verify failed: %v", selfResult.Error)
	}

	_ = rootKey
}

func TestVerify_ValidChainSM2(t *testing.T) {
	t.Parallel()

	root, _, intermediate, _, leaf, _ := createTestCAChainSM2(t)

	store, _ := crypto.NewTrustStore()
	store.AddCert(root)

	result, err := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate:   leaf,
		Intermediates: []*crypto.Certificate{intermediate},
		Roots:         store,
	})
	if err != nil {
		t.Fatalf("VerifyCertificate: %v", err)
	}
	if result.Error != nil {
		t.Fatalf("SM2 chain verification failed: %v (code=%d)", result.Error, result.ErrorCode)
	}
}

func TestVerify_SelfSignedTrusted(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateRSAKey(2048)
	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "CN",
		Organization: "Self Signed",
		CommonName:   "self.test",
	}
	cert, _ := crypto.NewCertificate(info, key)
	cert.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE")
	cert.Sign(key, crypto.DigestSHA256)

	store, _ := crypto.NewTrustStore()
	store.AddCert(cert)

	result, _ := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: cert,
		Roots:       store,
	})
	if result.Error != nil {
		t.Errorf("self-signed trusted cert failed: %v", result.Error)
	}
}

func TestVerify_SelfSignedUntrusted(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateRSAKey(2048)
	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "CN",
		Organization: "Untrusted",
		CommonName:   "untrusted.test",
	}
	cert, _ := crypto.NewCertificate(info, key)
	cert.Sign(key, crypto.DigestSHA256)

	store, _ := crypto.NewTrustStore()
	// Empty trust store, cert not trusted

	result, _ := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: cert,
		Roots:       store,
	})
	if result.Error == nil {
		t.Error("untrusted self-signed cert should fail verification")
	}
}

func TestVerify_MissingIntermediate(t *testing.T) {
	t.Parallel()

	root, _, _, _, leaf, _ := createTestCAChain(t)

	store, _ := crypto.NewTrustStore()
	store.AddCert(root)

	// Verify leaf without providing intermediate
	result, _ := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: leaf,
		Roots:       store,
	})
	if result.Error == nil {
		t.Error("should fail when intermediate is missing")
	}
}

func TestVerify_ExpiredCert(t *testing.T) {
	t.Parallel()

	key, _ := crypto.GenerateRSAKey(2048)
	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       -48 * time.Hour, // started 2 days ago
		Expires:      -24 * time.Hour, // expired yesterday
		Country:      "CN",
		Organization: "Expired",
		CommonName:   "expired.test",
	}
	cert, _ := crypto.NewCertificate(info, key)
	cert.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE")
	cert.Sign(key, crypto.DigestSHA256)

	store, _ := crypto.NewTrustStore()
	store.AddCert(cert)

	// Verify at current time (cert expired)
	result, _ := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: cert,
		Roots:       store,
	})
	if result.Error == nil {
		t.Error("expired cert should fail verification")
	}
}

func TestVerify_InvalidInput(t *testing.T) {
	t.Parallel()

	store, _ := crypto.NewTrustStore()

	_, err := crypto.VerifyCertificate(nil)
	if err == nil {
		t.Error("nil options should error")
	}

	_, err = crypto.VerifyCertificate(&crypto.VerifyOptions{})
	if err == nil {
		t.Error("nil certificate should error")
	}

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(1),
		Issued:       0,
		Expires:      time.Hour,
		Country:      "CN",
		Organization: "Test",
		CommonName:   "test",
	}
	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	_, err = crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: cert,
		// Roots is nil
	})
	if err == nil {
		t.Error("nil roots should error")
	}

	_ = store
}

func TestVerify_LoadCertsFromPEM(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// Create two self-signed certs
	cert1Info := &crypto.CertificateInfo{
		Serial: big.NewInt(1), Issued: 0, Expires: 24 * time.Hour,
		Country: "CN", Organization: "Root CA 1", CommonName: "root1.test",
	}
	cert1, err := crypto.NewCertificate(cert1Info, key)
	if err != nil {
		t.Fatal(err)
	}
	cert1.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE")
	if err := cert1.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	cert2Info := &crypto.CertificateInfo{
		Serial: big.NewInt(2), Issued: 0, Expires: 24 * time.Hour,
		Country: "CN", Organization: "Root CA 2", CommonName: "root2.test",
	}
	cert2, err := crypto.NewCertificate(cert2Info, key)
	if err != nil {
		t.Fatal(err)
	}
	cert2.AddExtension(crypto.NidBasicConstraints, "critical,CA:TRUE")
	if err := cert2.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	// Marshal both to PEM and concatenate
	pem1, err := cert1.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	pem2, err := cert2.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	combined := append(pem1, pem2...)

	store, err := crypto.NewTrustStore()
	if err != nil {
		t.Fatal(err)
	}

	if err := store.LoadCertsFromPEM(combined); err != nil {
		t.Fatalf("LoadCertsFromPEM: %v", err)
	}

	// Verify: cert1 should be trusted
	result, err := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: cert1,
		Roots:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Error != nil {
		t.Errorf("cert1 verification failed: %v", result.Error)
	}

	// Verify: cert2 should also be trusted
	result2, err := crypto.VerifyCertificate(&crypto.VerifyOptions{
		Certificate: cert2,
		Roots:       store,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result2.Error != nil {
		t.Errorf("cert2 verification failed: %v", result2.Error)
	}

	// Empty PEM should error (consistent with LoadCSRFromPEM, LoadCRLFromPEM)
	if err := store.LoadCertsFromPEM([]byte("")); err == nil {
		t.Error("LoadCertsFromPEM with empty data should error")
	}
}
