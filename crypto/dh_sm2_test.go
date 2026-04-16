package crypto_test

import (
	"bytes"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

// TestECDH_SM2 验证 SM2 ECDH 密钥协商
//
// 通过 EVP_PKEY_derive 通用路径测试 SM2 密钥的 ECDH 是否可用。
// 如果 Tongsuo 的 EVP_PKEY_derive 不支持 SM2，此测试将失败，
// 说明需要实现独立的 SM2 密钥交换路径。
func TestECDH_SM2(t *testing.T) {
	t.Parallel()

	alicePriv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("alice GenerateKey: %v", err)
	}

	bobPriv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("bob GenerateKey: %v", err)
	}

	alicePub := alicePriv.Public()
	bobPub := bobPriv.Public()

	// 使用固定盐值的 HKDF-SM3 配置，确保双方独立调用得到相同结果
	sm3KdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   make([]byte, 32), // 固定盐值
		KDFInfo:   []byte("sm2-ecdh-test"),
	}

	// Alice 用自己的私钥 + Bob 的公钥派生共享秘密
	aliceResult, err := crypto.DeriveSharedSecret(alicePriv, bobPub, sm3KdfConfig)
	if err != nil {
		t.Fatalf("alice DeriveSharedSecret: %v", err)
	}
	if !aliceResult.PeerPublicKeyValid {
		t.Error("alice: peer public key validation failed")
	}

	// Bob 用自己的私钥 + Alice 的公钥派生共享秘密
	bobResult, err := crypto.DeriveSharedSecret(bobPriv, alicePub, sm3KdfConfig)
	if err != nil {
		t.Fatalf("bob DeriveSharedSecret: %v", err)
	}
	if !bobResult.PeerPublicKeyValid {
		t.Error("bob: peer public key validation failed")
	}

	// 双方派生的密钥必须一致
	if !bytes.Equal(aliceResult.SharedSecret, bobResult.SharedSecret) {
		t.Errorf("shared secrets mismatch\nalice: %x\nbob:   %x",
			aliceResult.SharedSecret, bobResult.SharedSecret)
	}

	// 共享秘密长度应为 SM3 输出长度 (32 字节)
	if len(aliceResult.SharedSecret) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(aliceResult.SharedSecret))
	}

	t.Logf("SM2 ECDH shared secret (%d bytes): %x",
		len(aliceResult.SharedSecret), aliceResult.SharedSecret)
}

// TestECDH_SM2_DeriveBasic 验证 SM2 通过 DeriveSharedSecretBasic 路径
func TestECDH_SM2_DeriveBasic(t *testing.T) {
	t.Parallel()

	alicePriv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	bobPriv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	aliceSecret, err := crypto.DeriveSharedSecretBasic(alicePriv, bobPriv.Public())
	if err != nil {
		t.Fatalf("alice DeriveSharedSecretBasic: %v", err)
	}

	bobSecret, err := crypto.DeriveSharedSecretBasic(bobPriv, alicePriv.Public())
	if err != nil {
		t.Fatalf("bob DeriveSharedSecretBasic: %v", err)
	}

	if !bytes.Equal(aliceSecret, bobSecret) {
		t.Errorf("shared secrets differ\nalice: %x\nbob:   %x", aliceSecret, bobSecret)
	}
}

// TestECDH_SM2_UniqueSessions 验证不同密钥对产生不同的共享秘密
func TestECDH_SM2_UniqueSessions(t *testing.T) {
	t.Parallel()

	alice, _ := sm2.GenerateKey()
	bob, _ := sm2.GenerateKey()
	charlie, _ := sm2.GenerateKey()

	ab, _ := crypto.DeriveSharedSecretBasic(alice, bob.Public())
	ac, _ := crypto.DeriveSharedSecretBasic(alice, charlie.Public())

	if bytes.Equal(ab, ac) {
		t.Error("different peers should produce different shared secrets")
	}
}

// TestECDH_SM2_WithSecurityLevels 验证不同安全级别都能工作
func TestECDH_SM2_WithSecurityLevels(t *testing.T) {
	t.Parallel()

	priv1, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	priv2, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	kdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   make([]byte, 32),
		KDFInfo:   []byte("sm2-security-level-test"),
	}

	levels := []crypto.DHSecurityLevel{
		crypto.DHSecurityLevelBasic,
		crypto.DHSecurityLevelStandard,
		crypto.DHSecurityLevelHigh,
	}

	for _, level := range levels {
		result, err := crypto.DeriveSharedSecretWithSecurityLevel(
			priv1, priv2.Public(), kdfConfig, level)
		if err != nil {
			t.Errorf("security level %d: %v", level, err)
			continue
		}
		if !result.PeerPublicKeyValid {
			t.Errorf("security level %d: peer public key not valid", level)
		}
		if len(result.SharedSecret) != 32 {
			t.Errorf("security level %d: shared secret length = %d, want 32",
				level, len(result.SharedSecret))
		}
	}
}
