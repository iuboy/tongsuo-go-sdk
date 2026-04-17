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

package crypto

import (
	"crypto/rand"
	"math/big"
	"testing"
	"time"
)

// createTestCertificate 创建测试用自签名证书
func createTestCertificate(t *testing.T, key PrivateKey) *Certificate {
	t.Helper()

	serial, err := rand.Int(rand.Reader, big.NewInt(100000))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}

	info := &CertificateInfo{
		Serial:       serial,
		Issued:       -1 * time.Hour,       // 1小时前签发
		Expires:      24 * 365 * time.Hour, // 1年后过期
		Country:      "CN",
		Organization: "Test Org",
		CommonName:   "Test CA",
	}

	cert, err := NewCertificate(info, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	digest := DigestSHA256
	if key.KeyType() == KeyTypeSM2 {
		digest = DigestSM3
	}

	if err := cert.Sign(key, digest); err != nil {
		t.Fatalf("failed to sign certificate: %v", err)
	}

	return cert
}

func TestCreateOCSPResponse_SM2(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(12345)
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusGood, thisUpdate, nextUpdate, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("CreateOCSPResponse returned empty DER")
	}

	t.Logf("SM2 OCSP response DER length: %d bytes", len(der))
}

func TestCreateOCSPResponse_RSA(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(54321)
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusGood, thisUpdate, nextUpdate, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("CreateOCSPResponse returned empty DER")
	}

	t.Logf("RSA OCSP response DER length: %d bytes", len(der))
}

func TestCreateOCSPResponse_Revoked(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(99999)
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)
	revokedAt := thisUpdate.Add(-2 * time.Hour)

	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusRevoked, thisUpdate, nextUpdate, revokedAt)
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed for revoked status: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("CreateOCSPResponse returned empty DER for revoked status")
	}

	t.Logf("SM2 OCSP revoked response DER length: %d bytes", len(der))
}

func TestCreateOCSPResponse_Unknown(t *testing.T) {
	key, err := GenerateRSAKey(2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(11111)
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusUnknown, thisUpdate, nextUpdate, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed for unknown status: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("CreateOCSPResponse returned empty DER for unknown status")
	}
}

func TestParseOCSPResponse(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(77777)
	thisUpdate := time.Now().UTC().Truncate(time.Second)
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	// 创建响应
	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusGood, thisUpdate, nextUpdate, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed: %v", err)
	}

	// 解析响应
	resp, err := ParseOCSPResponse(der)
	if err != nil {
		t.Fatalf("ParseOCSPResponse failed: %v", err)
	}

	// 检查响应状态码
	if resp.GetStatus() != OCSPResponseStatusSuccessful {
		t.Fatalf("expected status %d, got %d", OCSPResponseStatusSuccessful, resp.GetStatus())
	}

	// 查找证书状态
	certStatus, _, parsedThis, parsedNext, _, err := resp.FindStatus(issuer, serial)
	if err != nil {
		t.Fatalf("FindStatus failed: %v", err)
	}

	if certStatus != OCSPStatusGood {
		t.Fatalf("expected cert status %d, got %d", OCSPStatusGood, certStatus)
	}

	// 验证时间一致性（允许一定误差）
	thisDiff := parsedThis.Sub(thisUpdate)
	if thisDiff < -2*time.Minute || thisDiff > 2*time.Minute {
		t.Logf("Warning: thisUpdate time diff: %v", thisDiff)
	}

	nextDiff := parsedNext.Sub(nextUpdate)
	if nextDiff < -2*time.Minute || nextDiff > 2*time.Minute {
		t.Logf("Warning: nextUpdate time diff: %v", nextDiff)
	}
}

func TestParseOCSPResponse_Revoked(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(88888)
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)
	revokedAt := thisUpdate.Add(-2 * time.Hour)

	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusRevoked, thisUpdate, nextUpdate, revokedAt)
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed: %v", err)
	}

	resp, err := ParseOCSPResponse(der)
	if err != nil {
		t.Fatalf("ParseOCSPResponse failed: %v", err)
	}

	certStatus, reason, _, _, parsedRevokedAt, err := resp.FindStatus(issuer, serial)
	if err != nil {
		t.Fatalf("FindStatus failed: %v", err)
	}

	if certStatus != OCSPStatusRevoked {
		t.Fatalf("expected cert status %d, got %d", OCSPStatusRevoked, certStatus)
	}

	if reason != OCSPReasonUnspecified {
		t.Fatalf("expected reason %d, got %d", OCSPReasonUnspecified, reason)
	}

	// 验证撤销时间
	revDiff := parsedRevokedAt.Sub(revokedAt)
	if revDiff < -2*time.Minute || revDiff > 2*time.Minute {
		t.Logf("Warning: revokedAt time diff: %v", revDiff)
	}
}

func TestParseOCSPResponse_WrongSerial(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(12345)
	thisUpdate := time.Now().UTC()
	nextUpdate := thisUpdate.Add(24 * time.Hour)

	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusGood, thisUpdate, nextUpdate, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed: %v", err)
	}

	resp, err := ParseOCSPResponse(der)
	if err != nil {
		t.Fatalf("ParseOCSPResponse failed: %v", err)
	}

	// 使用错误的序列号查找
	_, _, _, _, _, err = resp.FindStatus(issuer, big.NewInt(99999))
	if err == nil {
		t.Fatal("expected error for wrong serial number, got nil")
	}
}

func TestCreateOCSPResponse_NoNextUpdate(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}

	issuer := createTestCertificate(t, key)

	serial := big.NewInt(33333)
	thisUpdate := time.Now().UTC()

	// 不设置 nextUpdate
	der, err := CreateOCSPResponse(issuer, key, serial, OCSPStatusGood, thisUpdate, time.Time{}, time.Time{})
	if err != nil {
		t.Fatalf("CreateOCSPResponse failed without nextUpdate: %v", err)
	}

	if len(der) == 0 {
		t.Fatal("CreateOCSPResponse returned empty DER")
	}
}

func TestCreateOCSPResponse_InvalidInput(t *testing.T) {
	key, err := GenerateECKey(SM2Curve)
	if err != nil {
		t.Fatalf("failed to generate SM2 key: %v", err)
	}
	issuer := createTestCertificate(t, key)

	// nil issuer
	_, err = CreateOCSPResponse(nil, key, big.NewInt(1), OCSPStatusGood, time.Now(), time.Now(), time.Time{})
	if err == nil {
		t.Fatal("expected error for nil issuer")
	}

	// nil key
	_, err = CreateOCSPResponse(issuer, nil, big.NewInt(1), OCSPStatusGood, time.Now(), time.Now(), time.Time{})
	if err == nil {
		t.Fatal("expected error for nil key")
	}

	// nil serial
	_, err = CreateOCSPResponse(issuer, key, nil, OCSPStatusGood, time.Now(), time.Now(), time.Time{})
	if err == nil {
		t.Fatal("expected error for nil serial")
	}

	// negative serial
	_, err = CreateOCSPResponse(issuer, key, big.NewInt(-1), OCSPStatusGood, time.Now(), time.Now(), time.Time{})
	if err == nil {
		t.Fatal("expected error for negative serial")
	}
}

func TestParseOCSPResponse_EmptyInput(t *testing.T) {
	_, err := ParseOCSPResponse(nil)
	if err == nil {
		t.Fatal("expected error for nil input")
	}

	_, err = ParseOCSPResponse([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}
