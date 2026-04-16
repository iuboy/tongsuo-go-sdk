package crypto_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

func TestCRL_RSA(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	issuerName, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	issuerName.AddTextEntries(map[string]string{
		"C":  "CN",
		"O":  "Test CA",
		"CN": "Test CA RSA",
	})

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}

	if err := crl.SetIssuerName(issuerName); err != nil {
		t.Fatal(err)
	}

	now := time.Now().UTC()
	if err := crl.SetLastUpdate(now); err != nil {
		t.Fatalf("SetLastUpdate: %v", err)
	}
	if err := crl.SetNextUpdate(now.Add(7 * 24 * time.Hour)); err != nil {
		t.Fatalf("SetNextUpdate: %v", err)
	}

	rev, err := crypto.NewRevokedCertificate(big.NewInt(42), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.AddRevokedCertificate(rev); err != nil {
		t.Fatalf("AddRevokedCertificate: %v", err)
	}

	if err := crl.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatalf("Sign: %v", err)
	}
}

func TestCRL_SM2(t *testing.T) {
	t.Parallel()

	key, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	issuerName, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	issuerName.AddTextEntries(map[string]string{
		"C":  "CN",
		"O":  "Test CA",
		"CN": "Test CA SM2",
	})

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	crl.SetIssuerName(issuerName)

	now := time.Now().UTC()
	if err := crl.SetLastUpdate(now); err != nil {
		t.Fatal(err)
	}
	if err := crl.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	rev, err := crypto.NewRevokedCertificate(big.NewInt(100), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.AddRevokedCertificate(rev); err != nil {
		t.Fatal(err)
	}

	if err := crl.Sign(key, crypto.DigestSM3); err != nil {
		t.Fatalf("Sign SM2: %v", err)
	}
}

func TestCRL_PEMRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerName, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	issuerName.AddTextEntries(map[string]string{"CN": "CRL Test CA"})

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.SetIssuerName(issuerName); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := crl.SetLastUpdate(now); err != nil {
		t.Fatal(err)
	}
	if err := crl.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	rev, err := crypto.NewRevokedCertificate(big.NewInt(123), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.AddRevokedCertificate(rev); err != nil {
		t.Fatal(err)
	}
	if err := crl.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	pemBytes, err := crl.MarshalPEM()
	if err != nil {
		t.Fatalf("MarshalPEM: %v", err)
	}

	loaded, err := crypto.LoadCRLFromPEM(pemBytes)
	if err != nil {
		t.Fatalf("LoadCRLFromPEM: %v", err)
	}

	issuer, err := loaded.GetIssuerName()
	if err != nil {
		t.Fatal(err)
	}
	cn, ok := issuer.GetEntry(crypto.NidCommonName)
	if !ok || cn != "CRL Test CA" {
		t.Errorf("issuer CN = %q, want CRL Test CA", cn)
	}
}

func TestCRL_DERRoundTrip(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerName, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	issuerName.AddTextEntries(map[string]string{"CN": "CRL DER Test"})

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.SetIssuerName(issuerName); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := crl.SetLastUpdate(now); err != nil {
		t.Fatal(err)
	}
	if err := crl.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := crl.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	derBytes, err := crl.MarshalDER()
	if err != nil {
		t.Fatalf("MarshalDER: %v", err)
	}

	loaded, err := crypto.LoadCRLFromDER(derBytes)
	if err != nil {
		t.Fatalf("LoadCRLFromDER: %v", err)
	}

	issuer, err := loaded.GetIssuerName()
	if err != nil {
		t.Fatal(err)
	}
	cn, ok := issuer.GetEntry(crypto.NidCommonName)
	if !ok || cn != "CRL DER Test" {
		t.Errorf("issuer CN = %q, want CRL DER Test", cn)
	}
}

func TestCRL_RevokedCertificates(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerName, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	issuerName.AddTextEntries(map[string]string{"CN": "Multi Revoke CA"})

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.SetIssuerName(issuerName); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := crl.SetLastUpdate(now); err != nil {
		t.Fatal(err)
	}
	if err := crl.SetNextUpdate(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	serials := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(42)}
	for _, s := range serials {
		rev, err := crypto.NewRevokedCertificate(s, now)
		if err != nil {
			t.Fatal(err)
		}
		if err := crl.AddRevokedCertificate(rev); err != nil {
			t.Fatal(err)
		}
	}

	if err := crl.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	// Marshal and reload to test parsing
	pemBytes, err := crl.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := crypto.LoadCRLFromPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := loaded.GetRevokedCertificates()
	if err != nil {
		t.Fatalf("GetRevokedCertificates: %v", err)
	}
	if len(revoked) != 3 {
		t.Fatalf("got %d revoked entries, want 3", len(revoked))
	}

	// Verify serial numbers
	foundSerials := make(map[string]bool)
	for _, r := range revoked {
		sn := r.GetSerialNumber()
		if sn == nil {
			t.Error("nil serial number")
			continue
		}
		foundSerials[sn.String()] = true
	}
	for _, s := range serials {
		if !foundSerials[s.String()] {
			t.Errorf("serial %s not found in CRL", s)
		}
	}
}

func TestCRL_InvalidInput(t *testing.T) {
	t.Parallel()

	_, err := crypto.LoadCRLFromPEM(nil)
	if err == nil {
		t.Error("LoadCRLFromPEM(nil) should error")
	}

	_, err = crypto.LoadCRLFromDER(nil)
	if err == nil {
		t.Error("LoadCRLFromDER(nil) should error")
	}

	_, err = crypto.LoadCRLFromPEM([]byte("not a pem"))
	if err == nil {
		t.Error("LoadCRLFromPEM with garbage should error")
	}
}

func TestCRL_RevocationDateAccuracy(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerName, err := crypto.NewName()
	if err != nil {
		t.Fatal(err)
	}
	issuerName.AddTextEntries(map[string]string{"CN": "Date Test CA"})

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.SetIssuerName(issuerName); err != nil {
		t.Fatal(err)
	}

	expectedDate := time.Date(2025, 6, 15, 10, 30, 0, 0, time.UTC)
	if err := crl.SetLastUpdate(expectedDate); err != nil {
		t.Fatal(err)
	}
	if err := crl.SetNextUpdate(expectedDate.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}

	rev, err := crypto.NewRevokedCertificate(big.NewInt(99), expectedDate)
	if err != nil {
		t.Fatal(err)
	}
	if err := crl.AddRevokedCertificate(rev); err != nil {
		t.Fatal(err)
	}
	if err := crl.Sign(key, crypto.DigestSHA256); err != nil {
		t.Fatal(err)
	}

	// Round-trip to verify date survives serialization
	pemBytes, err := crl.MarshalPEM()
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := crypto.LoadCRLFromPEM(pemBytes)
	if err != nil {
		t.Fatal(err)
	}

	revoked, err := loaded.GetRevokedCertificates()
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 1 {
		t.Fatalf("got %d revoked entries, want 1", len(revoked))
	}

	gotDate, err := revoked[0].GetRevocationDate()
	if err != nil {
		t.Fatalf("GetRevocationDate: %v", err)
	}

	// ASN1_TIME only has second precision
	if gotDate.Unix() != expectedDate.Unix() {
		t.Errorf("revocation date = %v, want %v", gotDate, expectedDate)
	}
}

func TestCRL_UnsupportedDigest(t *testing.T) {
	t.Parallel()

	key, err := crypto.GenerateRSAKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	crl, err := crypto.NewCertificateRevocationList()
	if err != nil {
		t.Fatal(err)
	}

	if err := crl.Sign(key, crypto.DigestMD5); err == nil {
		t.Error("CRL Sign with MD5 should error")
	}
}
