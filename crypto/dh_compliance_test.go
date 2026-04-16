//go:build compliance

// SM2 ECDH 密钥协商合规测试
//
// 验证 SM2 密钥通过 ECDH 密钥协商的基本正确性和安全性。
//
// 注意: GM/T 0003.3 定义了完整的 SM2 密钥交换协议（包含临时密钥对、多轮交换），
// 这里测试的是基础 ECDH，适用于 TLS 握手等标准 ECDH 场景。
//
// 运行: go test -tags=compliance -v -run "TestCompliance_SM2_ECDH" ./crypto/

package crypto_test

import (
	"bytes"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

// TestCompliance_SM2_ECDH_Basic 验证 SM2 ECDH 基本密钥协商
//
// 双方各自使用自己的私钥和对方公钥派生共享秘密，
// 派生结果必须一致。
func TestCompliance_SM2_ECDH_Basic(t *testing.T) {
	t.Parallel()

	alice, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("alice GenerateKey: %v", err)
	}
	bob, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("bob GenerateKey: %v", err)
	}

	kdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   make([]byte, 32),
		KDFInfo:   []byte("sm2-ecdh-compliance-test"),
	}

	aliceResult, err := crypto.DeriveSharedSecret(alice, bob.Public(), kdfConfig)
	if err != nil {
		t.Fatalf("alice DeriveSharedSecret: %v", err)
	}
	if !aliceResult.PeerPublicKeyValid {
		t.Error("alice: peer public key validation failed")
	}

	bobResult, err := crypto.DeriveSharedSecret(bob, alice.Public(), kdfConfig)
	if err != nil {
		t.Fatalf("bob DeriveSharedSecret: %v", err)
	}
	if !bobResult.PeerPublicKeyValid {
		t.Error("bob: peer public key validation failed")
	}

	if !bytes.Equal(aliceResult.SharedSecret, bobResult.SharedSecret) {
		t.Errorf("shared secrets mismatch\nalice: %x\nbob:   %x",
			aliceResult.SharedSecret, bobResult.SharedSecret)
	}

	// SM3 KDF 输出 32 字节
	if len(aliceResult.SharedSecret) != 32 {
		t.Errorf("shared secret length = %d, want 32", len(aliceResult.SharedSecret))
	}
}

// TestCompliance_SM2_ECDH_DifferentPeers 验证不同密钥对产生不同共享秘密
//
// 安全性要求: 与不同对端协商应得到不同的共享秘密。
func TestCompliance_SM2_ECDH_DifferentPeers(t *testing.T) {
	t.Parallel()

	alice, _ := sm2.GenerateKey()
	bob, _ := sm2.GenerateKey()
	charlie, _ := sm2.GenerateKey()

	ab, err := crypto.DeriveSharedSecretBasic(alice, bob.Public())
	if err != nil {
		t.Fatal(err)
	}
	ac, err := crypto.DeriveSharedSecretBasic(alice, charlie.Public())
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ab, ac) {
		t.Error("different peers should produce different shared secrets")
	}
}

// TestCompliance_SM2_ECDH_RandomCiphertexts 验证每次 ECDH 协商结果不同
//
// 每次生成新的密钥对，ECDH 应产生不同的共享秘密。
func TestCompliance_SM2_ECDH_RandomCiphertexts(t *testing.T) {
	t.Parallel()

	kdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   make([]byte, 32),
		KDFInfo:   []byte("randomness-test"),
	}

	results := make([][]byte, 3)
	for i := 0; i < 3; i++ {
		a, _ := sm2.GenerateKey()
		b, _ := sm2.GenerateKey()
		r, err := crypto.DeriveSharedSecret(a, b.Public(), kdfConfig)
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		results[i] = r.SharedSecret
	}

	// 任意两次结果应不同（极大概率）
	if bytes.Equal(results[0], results[1]) {
		t.Error("sessions 0 and 1 produced same shared secret")
	}
	if bytes.Equal(results[1], results[2]) {
		t.Error("sessions 1 and 2 produced same shared secret")
	}
}

// TestCompliance_SM2_ECDH_SM3KDF 验证 SM2 ECDH 使用 SM3 KDF 派生密钥
//
// 使用 HKDF-SM3 作为密钥派生函数，符合 GB/T 37092-2018 国密 KDF 要求。
func TestCompliance_SM2_ECDH_SM3KDF(t *testing.T) {
	t.Parallel()

	alice, _ := sm2.GenerateKey()
	bob, _ := sm2.GenerateKey()

	sm3Config := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   []byte("fixed-salt-for-determinism"),
		KDFInfo:   []byte("sm3-kdf-test"),
	}

	aliceSecret, err := crypto.DeriveSharedSecret(alice, bob.Public(), sm3Config)
	if err != nil {
		t.Fatal(err)
	}

	bobSecret, err := crypto.DeriveSharedSecret(bob, alice.Public(), sm3Config)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(aliceSecret.SharedSecret, bobSecret.SharedSecret) {
		t.Errorf("HKDF-SM3 mismatch\nalice: %x\nbob:   %x",
			aliceSecret.SharedSecret, bobSecret.SharedSecret)
	}

	if len(aliceSecret.SharedSecret) != 32 {
		t.Errorf("SM3 KDF output = %d bytes, want 32", len(aliceSecret.SharedSecret))
	}
}

// TestCompliance_SM2_ECDH_Deterministic 验证相同输入产生相同输出
//
// 使用相同的密钥对和固定的 KDF 参数，结果应确定性。
func TestCompliance_SM2_ECDH_Deterministic(t *testing.T) {
	t.Parallel()

	alice, _ := sm2.GenerateKey()
	bob, _ := sm2.GenerateKey()

	kdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   []byte("deterministic-salt"),
		KDFInfo:   []byte("deterministic-info"),
	}

	result1, err := crypto.DeriveSharedSecret(alice, bob.Public(), kdfConfig)
	if err != nil {
		t.Fatal(err)
	}

	result2, err := crypto.DeriveSharedSecret(alice, bob.Public(), kdfConfig)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(result1.SharedSecret, result2.SharedSecret) {
		t.Errorf("same inputs should produce same output\nfirst:  %x\nsecond: %x",
			result1.SharedSecret, result2.SharedSecret)
	}
}

// TestCompliance_SM2_ECDH_WrongKey 验证用错误密钥协商失败
//
// 用 A 的私钥和 A 自己的公钥协商（而非对方公钥）应得到不同结果。
func TestCompliance_SM2_ECDH_WrongKey(t *testing.T) {
	t.Parallel()

	alice, _ := sm2.GenerateKey()
	bob, _ := sm2.GenerateKey()

	kdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   []byte("wrong-key-test"),
		KDFInfo:   []byte("test"),
	}

	// 正确协商: alice + bob
	correct, _ := crypto.DeriveSharedSecret(alice, bob.Public(), kdfConfig)

	// 错误协商: alice + alice (自协商)
	selfResult, err := crypto.DeriveSharedSecret(alice, alice.Public(), kdfConfig)
	if err != nil {
		t.Fatalf("self-derivation failed: %v", err)
	}

	if bytes.Equal(correct.SharedSecret, selfResult.SharedSecret) {
		t.Error("self-derivation should produce different secret than peer derivation")
	}
}

// TestCompliance_SM2_ECDH_SecurityLevels 验证所有安全级别都能工作
func TestCompliance_SM2_ECDH_SecurityLevels(t *testing.T) {
	t.Parallel()

	priv1, _ := sm2.GenerateKey()
	priv2, _ := sm2.GenerateKey()

	kdfConfig := &crypto.DHKDFConfig{
		UseKDF:    true,
		KDFDigest: crypto.SM3Method(),
		KDFSalt:   make([]byte, 32),
		KDFInfo:   []byte("security-level-test"),
	}

	for _, level := range []crypto.DHSecurityLevel{
		crypto.DHSecurityLevelNone,
		crypto.DHSecurityLevelBasic,
		crypto.DHSecurityLevelStandard,
		crypto.DHSecurityLevelHigh,
	} {
		result, err := crypto.DeriveSharedSecretWithSecurityLevel(
			priv1, priv2.Public(), kdfConfig, level)
		if err != nil {
			t.Errorf("security level %d: %v", level, err)
			continue
		}
		if level >= crypto.DHSecurityLevelBasic && !result.PeerPublicKeyValid {
			t.Errorf("security level %d: peer public key not valid", level)
		}
		if len(result.SharedSecret) != 32 {
			t.Errorf("security level %d: output length = %d, want 32",
				level, len(result.SharedSecret))
		}
	}
}
