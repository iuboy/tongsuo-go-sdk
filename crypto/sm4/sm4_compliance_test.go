//go:build compliance

// GM/T 0002-2012 SM4 分组密码算法合规测试
//
// 测试向量来源: GM/T 0002-2012 (等同于 GB/T 32907-2016) 标准文档
// 运行: go test -tags=compliance -v ./crypto/sm4/
// 报告: go test -json -tags=compliance ./crypto/sm4/

package sm4_test

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm4"
)

// GM/T 0002-2012 标准测试密钥和明文
var (
	gmtKey, _       = hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	gmtPlaintext, _ = hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	gmtIV, _        = hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
)

// TestCompliance_SM4_ECB_Vector 验证 SM4 ECB 模式的 GM/T 标准测试向量
//
// GM/T 0002-2012 第 5 节示例:
//
//	密钥:     0123456789ABCDEFFEDCBA9876543210
//	明文:     0123456789ABCDEFFEDCBA9876543210
//	密文:     681EDF34D206965E86B3E94F536E4246
func TestCompliance_SM4_ECB_Vector(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("681EDF34D206965E86B3E94F536E4246")

	// 使用 cipher.Block 接口 (底层 ECB)
	block, err := sm4.NewCipher(gmtKey)
	if err != nil {
		t.Fatalf("NewCipher: %v", err)
	}

	ciphertext := make([]byte, sm4.BlockSize)
	block.Encrypt(ciphertext, gmtPlaintext)

	if !bytes.Equal(ciphertext, expected) {
		t.Errorf("ECB encrypt mismatch\nexpect: %x\ngot:    %x", expected, ciphertext)
	}

	// 解密验证
	decrypted := make([]byte, sm4.BlockSize)
	block.Decrypt(decrypted, ciphertext)

	if !bytes.Equal(decrypted, gmtPlaintext) {
		t.Errorf("ECB decrypt mismatch\nexpect: %x\ngot:    %x", gmtPlaintext, decrypted)
	}
}

// TestCompliance_SM4_EVP_ECB 验证 EVP API 的 ECB 模式与 cipher.Block 一致
func TestCompliance_SM4_EVP_ECB(t *testing.T) {
	t.Parallel()

	expected, _ := hex.DecodeString("681EDF34D206965E86B3E94F536E4246")

	enc, err := sm4.NewEncrypter(crypto.CipherModeECB, gmtKey, nil)
	if err != nil {
		t.Fatalf("NewEncrypter: %v", err)
	}
	enc.SetPadding(false)

	got, err := enc.EncryptAll(gmtPlaintext)
	if err != nil {
		t.Fatalf("EncryptAll: %v", err)
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("EVP ECB mismatch\nexpect: %x\ngot:    %x", expected, got)
	}

	// 解密验证
	dec, err := sm4.NewDecrypter(crypto.CipherModeECB, gmtKey, nil)
	if err != nil {
		t.Fatalf("NewDecrypter: %v", err)
	}
	dec.SetPadding(false)

	plain, err := dec.DecryptAll(got)
	if err != nil {
		t.Fatalf("DecryptAll: %v", err)
	}

	if !bytes.Equal(plain, gmtPlaintext) {
		t.Errorf("EVP ECB decrypt mismatch\nexpect: %x\ngot:    %x", gmtPlaintext, plain)
	}
}

// TestCompliance_SM4_CBC 验证 SM4 CBC 模式
//
// GM/T 0002-2012 CBC 测试向量:
//
//	密钥:   0123456789ABCDEFFEDCBA9876543210
//	IV:     0123456789ABCDEFFEDCBA9876543210
//	明文:   0123456789ABCDEFFEDCBA9876543210 0123456789ABCDEFFEDCBA9876543210
//	密文:   2677F46B09C122CC975533105BD4A22A F6125F7275CE552C3A2BBCF533DE8A3B
func TestCompliance_SM4_CBC(t *testing.T) {
	t.Parallel()

	plaintext, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	expected, _ := hex.DecodeString("2677F46B09C122CC975533105BD4A22AF6125F7275CE552C3A2BBCF533DE8A3B")

	// cipher.Block + Go stdlib CBC
	block, err := sm4.NewCipher(gmtKey)
	if err != nil {
		t.Fatal(err)
	}

	enc := cipher.NewCBCEncrypter(block, gmtIV)
	ciphertext := make([]byte, len(plaintext))
	enc.CryptBlocks(ciphertext, plaintext)

	if !bytes.Equal(ciphertext, expected) {
		t.Errorf("CBC encrypt mismatch\nexpect: %x\ngot:    %x", expected, ciphertext)
	}

	// EVP API
	encEVP, err := sm4.NewEncrypter(crypto.CipherModeCBC, gmtKey, gmtIV)
	if err != nil {
		t.Fatal(err)
	}
	encEVP.SetPadding(false)
	gotEVP, err := encEVP.EncryptAll(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(gotEVP, expected) {
		t.Errorf("CBC EVP mismatch\nexpect: %x\ngot:    %x", expected, gotEVP)
	}
}

// TestCompliance_SM4_CFB 验证 SM4 CFB 模式
func TestCompliance_SM4_CFB(t *testing.T) {
	t.Parallel()

	plaintext, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	expected, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A70569ED258A85A0467CC92AAB393DD978995")

	enc, err := sm4.NewEncrypter(crypto.CipherModeCFB, gmtKey, gmtIV)
	if err != nil {
		t.Fatal(err)
	}
	enc.SetPadding(false)
	got, err := enc.EncryptAll(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("CFB mismatch\nexpect: %x\ngot:    %x", expected, got)
	}
}

// TestCompliance_SM4_OFB 验证 SM4 OFB 模式
func TestCompliance_SM4_OFB(t *testing.T) {
	t.Parallel()

	plaintext, _ := hex.DecodeString("0123456789ABCDEFFEDCBA98765432100123456789ABCDEFFEDCBA9876543210")
	expected, _ := hex.DecodeString("693D9A535BAD5BB1786F53D7253A7056F2075D28B5235F58D50027E4177D2BCE")

	enc, err := sm4.NewEncrypter(crypto.CipherModeOFB, gmtKey, gmtIV)
	if err != nil {
		t.Fatal(err)
	}
	enc.SetPadding(false)
	got, err := enc.EncryptAll(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got, expected) {
		t.Errorf("OFB mismatch\nexpect: %x\ngot:    %x", expected, got)
	}
}

// TestCompliance_SM4_Parameters 验证 SM4 算法参数符合 GM/T 0002-2012
//
// GM/T 0002-2012 规定:
//
//	分组长度: 128 比特 (16 字节)
//	密钥长度: 128 比特 (16 字节)
func TestCompliance_SM4_Parameters(t *testing.T) {
	t.Parallel()

	if sm4.BlockSize != 16 {
		t.Errorf("BlockSize = %d, want 16 (128 bits per GM/T 0002-2012)", sm4.BlockSize)
	}

	if sm4.KeySize != 16 {
		t.Errorf("KeySize = %d, want 16 (128 bits per GM/T 0002-2012)", sm4.KeySize)
	}
}

// TestCompliance_SM4_KeyValidation 验证密钥长度校验
//
// GM/T 0002-2012: 密钥长度固定为 128 比特
func TestCompliance_SM4_KeyValidation(t *testing.T) {
	t.Parallel()

	_, err := sm4.NewCipher(make([]byte, 15))
	if err == nil {
		t.Error("15-byte key should be rejected")
	}

	_, err = sm4.NewCipher(make([]byte, 17))
	if err == nil {
		t.Error("17-byte key should be rejected")
	}

	_, err = sm4.NewEncrypter(crypto.CipherModeECB, make([]byte, 8), nil)
	if err == nil {
		t.Error("8-byte key should be rejected for EVP encrypter")
	}
}

// TestCompliance_SM4_1MIterations GM/T 0002-2012 百万次加密验证
//
// 标准规定: 对明文 0123456789ABCDEFFEDCBA9876543210
// 使用密钥 0123456789ABCDEFFEDCBA9876543210
// 重复加密 1,000,000 次
// 期望结果: 595298C7C6FD271F0402F804C33D3F66
func TestCompliance_SM4_1MIterations(t *testing.T) {
	t.Parallel()

	key, _ := hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
	expected, _ := hex.DecodeString("595298C7C6FD271F0402F804C33D3F66")

	block, err := sm4.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, sm4.BlockSize)
	copy(data, gmtPlaintext)

	buf := make([]byte, sm4.BlockSize)
	for i := 0; i < 1000000; i++ {
		block.Encrypt(buf, data)
		data, buf = buf, data
	}

	if !bytes.Equal(data, expected) {
		t.Errorf("1M iterations mismatch\nexpect: %x\ngot:    %x", expected, data)
	}
}
