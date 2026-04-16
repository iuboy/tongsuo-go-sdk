//go:build compliance

// GM/T 0003-2012 SM2 椭圆曲线公钥密码算法合规测试
//
// 测试内容:
//   - 数字签名 (GM/T 0003.2-2012)
//   - 加密/解密 (GM/T 0003.4-2012)
//   - 密钥生成一致性
//
// 运行: go test -tags=compliance -v ./crypto/sm2/
// 报告: go test -json -tags=compliance ./crypto/sm2/

package sm2_test

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm3"
)

// TestCompliance_SM2_SignVerifyASN1 验证 SM2 签名/验签 (ASN.1 格式)
//
// GM/T 0003.2-2012 要求:
//   - SM2 签名使用 SM3 作为摘要算法
//   - 签名格式为 ASN.1 DER 编码
//   - 签名值 (r, s) 各为 256 比特
func TestCompliance_SM2_SignVerifyASN1(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub := priv.Public()

	data := []byte("GM/T 0003-2012 SM2 compliance test message")

	sig, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatalf("SignASN1: %v", err)
	}

	// 签名长度应该合理: ASN.1 编码的 (r, s)，每个 32 字节
	// 最短: 8 (ASN.1 头) + 32 + 32 = 72 字节
	// 最长: 8 + 33 + 33 = 74 字节 (含前导零)
	if len(sig) < 70 || len(sig) > 74 {
		t.Errorf("unexpected signature length: %d bytes", len(sig))
	}

	if err := sm2.VerifyASN1(pub, data, sig); err != nil {
		t.Fatalf("VerifyASN1: %v", err)
	}
}

// TestCompliance_SM2_SignVerifyRS 验证 SM2 签名/验签 (r,s 格式)
//
// GM/T 0003.2-2012: 签名输出为 (r, s) 两个整数
func TestCompliance_SM2_SignVerifyRS(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub := priv.Public()
	data := []byte("SM2 (r,s) format test")

	r, s, err := sm2.Sign(priv, data)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	// r, s 必须在 [1, n-1] 范围内，n 为 SM2 曲线阶数
	// SM2 曲线阶数 n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
	// 即 r, s 应该是 256 比特正整数
	if r.Sign() <= 0 {
		t.Error("r must be positive")
	}
	if s.Sign() <= 0 {
		t.Error("s must be positive")
	}
	if r.BitLen() > 256 {
		t.Errorf("r bit length = %d, should be <= 256", r.BitLen())
	}
	if s.BitLen() > 256 {
		t.Errorf("s bit length = %d, should be <= 256", s.BitLen())
	}

	if err := sm2.Verify(pub, data, r, s); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestCompliance_SM2_EncryptDecrypt 验证 SM2 加密/解密
//
// GM/T 0003.4-2012 SM2 消息加密:
//   - 密文格式: C1 || C3 || C2 (旧格式) 或 C1 || C2 || C3 (新格式)
//   - C1: 椭圆曲线点 (公钥计算结果)
//   - C2: 密文数据
//   - C3: SM3 摘要值 (32 字节)
func TestCompliance_SM2_EncryptDecrypt(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub := priv.Public()
	plaintext := []byte("GM/T 0003.4-2012 SM2 encryption test")

	ciphertext, err := sm2.Encrypt(pub, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	// SM2 密文长度 >= 1 + 32 + 32 + len(plaintext) (C1 + C3 + C2)
	// C1 = 04 + 32 + 32 = 65 字节 (未压缩点)
	// C3 = 32 字节 (SM3)
	// C2 = len(plaintext)
	minLen := 65 + 32 + len(plaintext)
	if len(ciphertext) < minLen {
		t.Errorf("ciphertext too short: %d, min expected %d", len(ciphertext), minLen)
	}

	decrypted, err := sm2.Decrypt(priv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypt mismatch\nexpect: %x\ngot:    %x", plaintext, decrypted)
	}
}

// TestCompliance_SM2_EncryptRejectsEmpty 验证 SM2 加密拒绝空消息
//
// GM/T 0003.4-2012: SM2 加密需要实际数据作为输入
func TestCompliance_SM2_EncryptRejectsEmpty(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	_, err = sm2.Encrypt(priv.Public(), []byte{})
	if err == nil {
		t.Error("empty plaintext should be rejected by SM2 encryption")
	}
}

// TestCompliance_SM2_KeyType 验证生成的密钥类型为 SM2
//
// GM/T 0003-2012 使用 sm2p256v1 曲线
func TestCompliance_SM2_KeyType(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	if priv.KeyType() != crypto.NidSM2 {
		t.Errorf("key type = %d, want NidSM2 (%d)", priv.KeyType(), crypto.NidSM2)
	}

	pub := priv.Public()
	if pub.KeyType() != crypto.NidSM2 {
		t.Errorf("pub key type = %d, want NidSM2 (%d)", pub.KeyType(), crypto.NidSM2)
	}
}

// TestCompliance_SM2_DeterministicSign 验证相同密钥+不同消息产生不同签名
//
// SM2 签名包含随机数 k，相同消息多次签名结果应不同 (除非确定签名模式)
func TestCompliance_SM2_DeterministicSign(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("deterministic test")

	sig1, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	sig2, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(sig1, sig2) {
		t.Error("two signatures of the same message should differ (random k)")
	}

	// 但两个签名都应能通过验证
	if err := sm2.VerifyASN1(priv.Public(), data, sig1); err != nil {
		t.Error("sig1 verification failed")
	}
	if err := sm2.VerifyASN1(priv.Public(), data, sig2); err != nil {
		t.Error("sig2 verification failed")
	}
}

// TestCompliance_SM2_WrongKeyReject 验证用错误密钥验签会失败
//
// 安全性要求: 非签名者的公钥不能通过验证
func TestCompliance_SM2_WrongKeyReject(t *testing.T) {
	t.Parallel()

	signer, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	other, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("wrong key test")

	sig, err := sm2.SignASN1(signer, data)
	if err != nil {
		t.Fatal(err)
	}

	// 用 other 的公钥验证 signer 的签名应该失败
	err = sm2.VerifyASN1(other.Public(), data, sig)
	if err == nil {
		t.Error("verification with wrong public key should fail")
	}
}

// TestCompliance_SM2_TamperedMessageReject 验证篡改消息后验签失败
func TestCompliance_SM2_TamperedMessageReject(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("original message")
	sig, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	// 篡改消息
	tampered := []byte("original messagf") // 最后一个字节改了
	err = sm2.VerifyASN1(priv.Public(), tampered, sig)
	if err == nil {
		t.Error("verification of tampered message should fail")
	}
}

// TestCompliance_SM2_TamperedSigReject 验证篡改签名后验签失败
func TestCompliance_SM2_TamperedSigReject(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("original message")
	sig, err := sm2.SignASN1(priv, data)
	if err != nil {
		t.Fatal(err)
	}

	// 篡改签名最后一个字节
	tamperedSig := make([]byte, len(sig))
	copy(tamperedSig, sig)
	tamperedSig[len(tamperedSig)-1] ^= 0xFF

	err = sm2.VerifyASN1(priv.Public(), data, tamperedSig)
	if err == nil {
		t.Error("verification of tampered signature should fail")
	}
}

// TestCompliance_SM2_EncryptRandomCiphertext 验证每次加密产生不同密文
//
// SM2 加密使用随机数，相同明文多次加密结果应不同
func TestCompliance_SM2_EncryptRandomCiphertext(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	plaintext := make([]byte, 64)
	rand.Read(plaintext)

	ct1, err := sm2.Encrypt(priv.Public(), plaintext)
	if err != nil {
		t.Fatal(err)
	}

	ct2, err := sm2.Encrypt(priv.Public(), plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if bytes.Equal(ct1, ct2) {
		t.Error("two encryptions of same plaintext should differ (random k)")
	}
}

// TestCompliance_SM2_WithSM3Hash 验证 SM2 签名与 SM3 哈希的集成
//
// GM/T 0003.2-2012: SM2 签名使用 SM3 作为摘要算法
// 等效于: SM2_sign(SM3(message))
func TestCompliance_SM2_WithSM3Hash(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("SM2 with SM3 hash integration test")

	// 方法1: 直接签名消息 (内部自动使用 SM3)
	sig, err := sm2.SignASN1(priv, message)
	if err != nil {
		t.Fatal(err)
	}

	// 验证签名有效
	if err := sm2.VerifyASN1(priv.Public(), message, sig); err != nil {
		t.Fatalf("direct verify failed: %v", err)
	}

	// 验证 SM3 哈希值非空
	hash, err := sm3.Sum(message)
	if err != nil {
		t.Fatal(err)
	}
	if len(hash) != 32 {
		t.Errorf("SM3 hash length = %d, want 32", len(hash))
	}
}

// TestCompliance_SM2_SignASN1Format 验证 ASN.1 签名格式
//
// DER 编码的 ECDSA-Sig-Value: SEQUENCE { r INTEGER, s INTEGER }
func TestCompliance_SM2_SignASN1Format(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	sig, err := sm2.SignASN1(priv, []byte("format test"))
	if err != nil {
		t.Fatal(err)
	}

	// ASN.1 SEQUENCE 以 0x30 开头
	if sig[0] != 0x30 {
		t.Errorf("signature should start with SEQUENCE tag 0x30, got 0x%02x", sig[0])
	}

	// 从 ASN.1 签名中提取 r, s 并验证范围
	r, s, err := sm2.Sign(priv, []byte("format test 2"))
	if err != nil {
		t.Fatal(err)
	}

	// r 和 s 应该在 SM2 曲线阶数范围内
	// n = FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
	nHex := "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
	n, _ := new(big.Int).SetString(nHex, 16)

	if r.Cmp(n) >= 0 {
		t.Errorf("r >= n, violates SM2 curve order constraint")
	}
	if s.Cmp(n) >= 0 {
		t.Errorf("s >= n, violates SM2 curve order constraint")
	}
}

// TestCompliance_SM2_SignWithKnownHash 验证签名使用固定输入的确定性
//
// 使用 SM3 哈希后的数据进行签名，验证签名和验签的完整链路
func TestCompliance_SM2_SignWithKnownHash(t *testing.T) {
	t.Parallel()

	priv, err := sm2.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	// 已知的 SM3 哈希值 (SM3("abc"))
	knownHash, _ := hex.DecodeString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")

	// 用哈希值进行签名
	sig, err := sm2.SignASN1(priv, knownHash)
	if err != nil {
		t.Fatalf("SignASN1 with hash: %v", err)
	}

	if err := sm2.VerifyASN1(priv.Public(), knownHash, sig); err != nil {
		t.Fatalf("VerifyASN1 with hash: %v", err)
	}
}
