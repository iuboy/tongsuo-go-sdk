// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package crypto_test

import (
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

func TestCertGenerate(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}

	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}
}

func TestCertGenerateSM2(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}

	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.Sign(key, crypto.DigestSM3); err != nil {
		t.Fatal(err)
	}
}

func TestCAGenerate(t *testing.T) {
	t.Parallel()

	cakey, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test CA",
		CommonName:   "CA",
	}

	ca, err := crypto.NewCertificate(info, cakey)
	if err != nil {
		t.Fatal(err)
	}

	if err := ca.AddExtensions(map[crypto.NID]string{
		crypto.NidBasicConstraints:     "critical,CA:TRUE",
		crypto.NidKeyUsage:             "critical,keyCertSign,cRLSign",
		crypto.NidSubjectKeyIdentifier: "hash",
		crypto.NidNetscapeCertType:     "sslCA",
	}); err != nil {
		t.Fatal(err)
	}

	if err := ca.Sign(cakey, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	info = &crypto.CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}

	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.AddExtensions(map[crypto.NID]string{
		crypto.NidBasicConstraints: "critical,CA:FALSE",
		crypto.NidKeyUsage:         "keyEncipherment",
		crypto.NidExtKeyUsage:      "serverAuth",
	}); err != nil {
		t.Fatal(err)
	}

	if err := cert.SetIssuer(ca); err != nil {
		t.Fatal(err)
	}

	if err := cert.Sign(cakey, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}
}

func generateSM2KeyAndSave(t *testing.T, filename string) crypto.PrivateKey {
	t.Helper()

	key, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	pem, err := key.MarshalPKCS8PrivateKeyPEM()
	if err != nil {
		t.Fatal(err)
	}

	err = crypto.SavePEMToFile(pem, filename)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func TestCAGenerateSM2(t *testing.T) {
	t.Parallel()

	dirName := filepath.Join("test-runs", "TestCAGenerateSM2")
	_, err := os.Stat(dirName)

	if os.IsNotExist(err) {
		err := os.MkdirAll(dirName, 0o755)
		if err != nil {
			t.Logf("Failed to create the directory: %v\n", err)
		}
	} else if err != nil {
		t.Logf("Failed to check the directory: %v\n", err)
	}

	signAndSaveCert := func(cert *crypto.Certificate, caKey crypto.PrivateKey, filename string) {
		err := cert.Sign(caKey, crypto.DigestSM3)
		if err != nil {
			t.Fatal(err)
		}

		certPem, err := cert.MarshalPEM()
		if err != nil {
			t.Fatal(err)
		}

		err = crypto.SavePEMToFile(certPem, filename)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Create CA certificate
	caKey, err := crypto.GenerateECKey(crypto.SM2Curve)
	if err != nil {
		t.Fatal(err)
	}

	caInfo := crypto.CertificateInfo{
		big.NewInt(1),
		0,
		87600 * time.Hour, // 10 years
		"US",
		"Test CA",
		"CA",
	}
	caExtensions := map[crypto.NID]string{
		crypto.NidBasicConstraints:       "critical,CA:TRUE",
		crypto.NidKeyUsage:               "critical,digitalSignature,keyCertSign,cRLSign",
		crypto.NidSubjectKeyIdentifier:   "hash",
		crypto.NidAuthorityKeyIdentifier: "keyid:always,issuer",
	}

	ca, err := crypto.NewCertificate(&caInfo, caKey)
	if err != nil {
		t.Fatal(err)
	}

	err = ca.AddExtensions(caExtensions)
	if err != nil {
		t.Fatal(err)
	}

	caFile := filepath.Join(dirName, "chain-ca.crt")
	signAndSaveCert(ca, caKey, caFile)

	certInfos := []struct {
		name     string
		keyUsage string
	}{
		{"server_enc", "keyAgreement, keyEncipherment, dataEncipherment"},
		{"server_sign", "nonRepudiation, digitalSignature"},
		{"client_sign", "nonRepudiation, digitalSignature"},
		{"client_enc", "keyAgreement, keyEncipherment, dataEncipherment"},
	}

	for _, info := range certInfos {
		keyFile := filepath.Join(dirName, info.name+".key")
		key := generateSM2KeyAndSave(t, keyFile)
		certInfo := crypto.CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       0,
			Expires:      87600 * time.Hour, // 10 years
			Country:      "US",
			Organization: "Test",
			CommonName:   "localhost",
		}
		extensions := map[crypto.NID]string{
			crypto.NidBasicConstraints: "critical,CA:FALSE",
			crypto.NidKeyUsage:         info.keyUsage,
		}

		cert, err := crypto.NewCertificate(&certInfo, key)
		if err != nil {
			t.Fatal(err)
		}

		err = cert.AddExtensions(extensions)
		if err != nil {
			t.Fatal(err)
		}

		err = cert.SetIssuer(ca)
		if err != nil {
			t.Fatal(err)
		}

		certFile := filepath.Join(dirName, info.name+".crt")
		signAndSaveCert(cert, caKey, certFile)
	}
}

func TestCertGetNameEntry(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}

	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	name, err := cert.GetSubjectName()
	if err != nil {
		t.Fatal(err)
	}

	entry, ok := name.GetEntry(crypto.NidCommonName)
	if !ok {
		t.Fatal("no common name")
	}

	if entry != "localhost" {
		t.Fatalf("expected localhost; got %q", entry)
	}

	entry, ok = name.GetEntry(crypto.NidLocalityName)
	if ok {
		t.Fatal("did not expect a locality name")
	}

	if entry != "" {
		t.Fatalf("entry should be empty; got %q", entry)
	}
}

func TestCertVersion(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(int64(1)),
		Issued:       0,
		Expires:      24 * time.Hour,
		Country:      "US",
		Organization: "Test",
		CommonName:   "localhost",
	}

	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	if err := cert.SetVersion(crypto.X509V3); err != nil {
		t.Fatal(err)
	}

	if vers := cert.GetVersion(); vers != crypto.X509V3 {
		t.Fatalf("bad version: %d", vers)
	}
}

func TestToX509Certificate(t *testing.T) {
	t.Parallel()

	t.Run("RSA", func(t *testing.T) {
		t.Parallel()
		key, err := crypto.GenerateRSAKey(2048)
		if err != nil {
			t.Fatal(err)
		}

		info := &crypto.CertificateInfo{
			Serial:       big.NewInt(1),
			Issued:       24 * time.Hour,
			Expires:      24 * time.Hour,
			CommonName:   "test-tox509",
			Country:      "CN",
			Organization: "Test",
		}

		cert, err := crypto.NewCertificate(info, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.Sign(key, crypto.DigestSHA256); err != nil {
			t.Fatal(err)
		}

		goCert, err := cert.ToX509Certificate()
		if err != nil {
			t.Fatalf("ToX509Certificate failed: %v", err)
		}
		if goCert.Subject.CommonName != "test-tox509" {
			t.Fatalf("expected CN=test-tox509, got %q", goCert.Subject.CommonName)
		}
		if goCert.Subject.Organization[0] != "Test" {
			t.Fatalf("expected O=Test, got %v", goCert.Subject.Organization)
		}
		if goCert.Subject.Country[0] != "CN" {
			t.Fatalf("expected C=CN, got %v", goCert.Subject.Country)
		}
	})

	t.Run("SM2", func(t *testing.T) {
		t.Parallel()
		key, err := crypto.GenerateECKey(crypto.SM2Curve)
		if err != nil {
			t.Fatal(err)
		}

		info := &crypto.CertificateInfo{
			Serial:       big.NewInt(2),
			Issued:       24 * time.Hour,
			Expires:      24 * time.Hour,
			CommonName:   "sm2-test",
			Country:      "CN",
			Organization: "GMTest",
		}

		cert, err := crypto.NewCertificate(info, key)
		if err != nil {
			t.Fatal(err)
		}
		if err := cert.Sign(key, crypto.DigestSM3); err != nil {
			t.Fatal(err)
		}

		goCert, err := cert.ToX509Certificate()
		if err != nil {
			t.Skipf("SM2 cert: %v", err)
		}
		if goCert.Subject.CommonName != "sm2-test" {
			t.Fatalf("expected CN=sm2-test, got %q", goCert.Subject.CommonName)
		}
	})
}

func TestAddExtensionByOID(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	info := &crypto.CertificateInfo{
		Serial:       big.NewInt(42),
		Issued:       24 * time.Hour,
		Expires:      24 * time.Hour,
		CommonName:   "ext-test",
		Country:      "CN",
		Organization: "Test",
	}

	cert, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}

	// Add a custom extension using OID for "1.2.3.4.5.6" (test OID)
	testValue := []byte{0x04, 0x04, 0xde, 0xad, 0xbe, 0xef} // OCTET STRING wrapper
	if err := cert.AddExtensionByOID("1.2.3.4.5.6", false, testValue); err != nil {
		t.Fatalf("AddExtensionByOID failed: %v", err)
	}

	// Sign to finalize the certificate
	if err := cert.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	// Convert to stdlib and verify the extension exists
	goCert, err := cert.ToX509Certificate()
	if err != nil {
		t.Fatalf("ToX509Certificate failed: %v", err)
	}

	found := false
	for _, ext := range goCert.Extensions {
		if ext.Id.String() == "1.2.3.4.5.6" {
			found = true
			if ext.Critical {
				t.Error("extension should not be critical")
			}
			break
		}
	}
	if !found {
		t.Error("custom OID extension 1.2.3.4.5.6 not found in certificate")
	}

	// Test critical extension
	cert2, err := crypto.NewCertificate(info, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert2.AddExtensionByOID("1.2.3.4.5.7", true, testValue); err != nil {
		t.Fatalf("AddExtensionByOID (critical) failed: %v", err)
	}
	if err := cert2.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}
	goCert2, err := cert2.ToX509Certificate()
	if err != nil {
		t.Fatalf("ToX509Certificate failed: %v", err)
	}
	for _, ext := range goCert2.Extensions {
		if ext.Id.String() == "1.2.3.4.5.7" {
			if !ext.Critical {
				t.Error("extension should be critical")
			}
			break
		}
	}
}
