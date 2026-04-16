package crypto_test

import (
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

func TestCSR_RSA(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	name, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	if err := name.AddTextEntries(map[string]string{
		"C":  "CN",
		"O":  "Test",
		"CN": "test.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := csr.SetSubjectName(name); err != nil {
		t.Fatal(err)
	}

	if err := csr.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}
}

func TestCSR_SM2(t *testing.T) {
	t.Parallel()

	key, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	name, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	if err := name.AddTextEntries(map[string]string{
		"C":  "CN",
		"O":  "Test",
		"CN": "sm2.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := csr.SetSubjectName(name); err != nil {
		t.Fatal(err)
	}

	if err := csr.Sign(key, crypto.DigestSM3); err != nil {
		t.Fatal(err)
	}
}

func TestCSR_PEMRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	name, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	name.AddTextEntry("CN", "roundtrip.test")

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}
	csr.SetSubjectName(name)
	if err := csr.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	pemBytes, err := csr.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}

	loaded, err := crypto.LoadCSRFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("LoadCSRFromPEM: %v", err)
	}

	subj, err := loaded.GetSubjectName()
	if err != nil {
		t.Fatal(err)
	}
	cn, ok := subj.GetEntry(crypto.NidCommonName)
	if !ok || cn != "roundtrip.test" {
		t.Errorf("CN = %q, want roundtrip.test", cn)
	}
}

func TestCSR_DERRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	name, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	name.AddTextEntry("CN", "der.test")

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}
	csr.SetSubjectName(name)
	if err := csr.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	derBytes, err := csr.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}

	loaded, err := crypto.LoadCSRFromDER(derBytes)
	if err != nil {
		t.Fatalf("LoadCSRFromDER: %v", err)
	}

	subj, err := loaded.GetSubjectName()
	if err != nil {
		t.Fatal(err)
	}
	cn, ok := subj.GetEntry(crypto.NidCommonName)
	if !ok || cn != "der.test" {
		t.Errorf("CN = %q, want der.test", cn)
	}
}

func TestCSR_WithExtensions(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}

	name, _ := crypto.NewName()
	name.AddTextEntry("CN", "ext.test")
	csr.SetSubjectName(name)

	if err := csr.AddExtension(crypto.NidKeyUsage, "digitalSignature,keyEncipherment"); err != nil {
		t.Fatalf("AddExtension keyUsage: %v", err)
	}
	if err := csr.AddExtension(crypto.NidExtKeyUsage, "serverAuth,clientAuth"); err != nil {
		t.Fatalf("AddExtension extKeyUsage: %v", err)
	}

	if err := csr.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestCSR_InvalidInput(t *testing.T) {
	t.Parallel()

	_, err := crypto.LoadCSRFromPEM(nil)
	if err == nil {
		t.Error("LoadCSRFromPEM(nil) should error")
	}

	_, err = crypto.LoadCSRFromDER(nil)
	if err == nil {
		t.Error("LoadCSRFromDER(nil) should error")
	}

	_, err = crypto.LoadCSRFromPEM([]byte("not a pem"))
	if err == nil {
		t.Error("LoadCSRFromPEM with invalid data should error")
	}
}

func TestCSR_GetPublicKey(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := csr.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}
	if pubKey == nil {
		t.Fatal("GetPublicKey returned nil")
	}

	// Verify the public key matches the original key type
	origPub := key.Public()
	if pubKey.KeyType() != origPub.KeyType() {
		t.Errorf("key type mismatch: got %d, want %d", pubKey.KeyType(), origPub.KeyType())
	}
}

func TestCSR_AddExtensionInvalidInput(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}

	// Invalid NID
	if err := csr.AddExtension(crypto.NID(0), "digitalSignature"); err == nil {
		t.Error("AddExtension with NID 0 should error")
	}

	// Empty value
	if err := csr.AddExtension(crypto.NidKeyUsage, ""); err == nil {
		t.Error("AddExtension with empty value should error")
	}
}

func TestCSR_UnsupportedDigest(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	csr, err := crypto.NewCertificateSigningRequest(key)
	if err != nil {
		t.Fatal(err)
	}

	if err := csr.Sign(key, crypto.DigestMD5); err == nil {
		t.Error("Sign with MD5 digest should error")
	}
}
