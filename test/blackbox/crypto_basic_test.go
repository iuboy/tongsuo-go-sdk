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

package blackbox_tests

import (
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// TestHMAC 测试HMAC功能
func TestHMAC(t *testing.T) {
	if !tongsuoAvailable() {
		t.Skip("Tongsuo not available")
	}

	t.Run("HMAC-SHA256 basic operation", func(t *testing.T) {
		key := []byte("secret-key-32-bytes-long-test-key!")
		data := []byte("data to authenticate")

		// 创建HMAC
		hmac, err := crypto.NewHMAC(key, crypto.DigestSHA256)
		if err != nil {
			t.Fatalf("Failed to create HMAC: %v", err)
		}

		hmac.Write(data)
		mac, err := hmac.Final()
		if err != nil {
			t.Fatalf("Failed to finalize HMAC: %v", err)
		}

		if len(mac) == 0 {
			t.Fatal("Empty MAC returned")
		}

		t.Logf("HMAC-SHA256 length: %d bytes", len(mac))
	})

	t.Run("HMAC-SM3 operation", func(t *testing.T) {
		key := []byte("sm3-test-key-32-bytes-long-test!!")
		data := []byte("SM3 HMAC test data")

		hmac, err := crypto.NewHMAC(key, crypto.DigestSM3)
		if err != nil {
			t.Fatalf("Failed to create SM3 HMAC: %v", err)
		}

		hmac.Write(data)
		mac, err := hmac.Final()
		if err != nil {
			t.Fatalf("Failed to finalize SM3 HMAC: %v", err)
		}

		if len(mac) == 0 {
			t.Fatal("Empty SM3 MAC returned")
		}

		t.Logf("SM3 HMAC length: %d bytes", len(mac))
	})
}

// TestKeyGeneration 测试密钥生成
func TestKeyGeneration(t *testing.T) {
	if !tongsuoAvailable() {
		t.Skip("Tongsuo not available")
	}

	t.Run("RSA key generation minimum size", func(t *testing.T) {
		// 测试最小密钥长度要求
		_, err := crypto.GenerateRSAKey(1024)
		if err == nil {
			t.Error("Expected error for RSA key size < 2048")
		}

		// 测试最小安全密钥长度
		key, err := crypto.GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("Failed to generate 2048-bit RSA key: %v", err)
		}
		defer key.Wipe()

		if key.KeyType() != crypto.KeyTypeRSA && key.KeyType() != crypto.KeyTypeRSA2 {
			t.Errorf("Expected RSA key type, got %v", key.KeyType())
		}
	})

	t.Run("EC key generation", func(t *testing.T) {
		curves := []struct {
			name  string
			curve crypto.EllipticCurve
		}{
			{"P-256", crypto.Prime256v1},
			{"P-384", crypto.Secp384r1},
			{"SM2", crypto.SM2Curve},
		}

		for _, tc := range curves {
			t.Run(tc.name, func(t *testing.T) {
				key, err := crypto.GenerateECKey(tc.curve)
				if err != nil {
					t.Fatalf("Failed to generate %s key: %v", tc.name, err)
				}
				defer key.Wipe()

				pubKey := key.Public()
				if pubKey == nil {
					t.Fatal("Failed to get public key")
				}
			})
		}
	})
}

// TestKeyWipe 测试密钥销毁
func TestKeyWipe(t *testing.T) {
	if !tongsuoAvailable() {
		t.Skip("Tongsuo not available")
	}

	t.Run("wipe and verify", func(t *testing.T) {
		key, err := crypto.GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("Failed to generate RSA key: %v", err)
		}

		// 验证密钥正常工作
		pub := key.Public()
		if pub == nil {
			t.Fatal("Failed to get public key before wipe")
		}

		// 销毁密钥
		err = key.Wipe()
		if err != nil {
			t.Fatalf("Failed to wipe key: %v", err)
		}

		// 再次销毁应该返回错误
		err = key.Wipe()
		if err == nil {
			t.Error("Expected error when wiping already-wiped key")
		}
	})

	t.Run("wipe works for EC keys", func(t *testing.T) {
		// 测试EC密钥销毁（ARM64上也可能失败）
		key, err := crypto.GenerateECKey(crypto.Prime256v1)
		if err != nil {
			t.Fatalf("Failed to generate EC key: %v", err)
		}

		err = key.Wipe()
		if err != nil {
			t.Errorf("Failed to wipe EC key: %v", err)
		}
	})
}

// TestSignOptions 测试签名选项
func TestSignOptions(t *testing.T) {
	t.Run("SignOptions struct can be created", func(t *testing.T) {
		opts := &crypto.SignOptions{
			SM2ID:      "test@example.com",
			SM2IDIsHex: false,
		}

		if opts.SM2ID != "test@example.com" {
			t.Errorf("Expected SM2ID 'test@example.com', got '%s'", opts.SM2ID)
		}

		if opts.SM2IDIsHex != false {
			t.Error("Expected SM2IDIsHex to be false")
		}
	})

	t.Run("DefaultSM2SignOptions returns valid options", func(t *testing.T) {
		opts := crypto.DefaultSM2SignOptions()
		if opts == nil {
			t.Fatal("DefaultSM2SignOptions returned nil")
		}

		t.Logf("Default SM2 ID: %s", opts.SM2ID)
		t.Logf("Default SM2 ID is hex: %v", opts.SM2IDIsHex)
	})
}

// TestErrorHandling 测试错误处理
func TestErrorHandling(t *testing.T) {
	if !tongsuoAvailable() {
		t.Skip("Tongsuo not available")
	}

	t.Run("invalid curve", func(t *testing.T) {
		invalidCurve := crypto.EllipticCurve(99999)
		_, err := crypto.GenerateECKey(invalidCurve)
		if err == nil {
			t.Error("Expected error for invalid curve")
		}
	})

	t.Run("empty HMAC key", func(t *testing.T) {
		emptyKey := []byte{}
		_, err := crypto.NewHMAC(emptyKey, crypto.DigestSHA256)
		if err == nil {
			t.Error("Expected error for empty HMAC key")
		}
	})
}

// TestConstants 测试常量定义
func TestConstants(t *testing.T) {
	t.Run("digest algorithm constants", func(t *testing.T) {
		constants := []crypto.DigestAlgo{
			crypto.DigestNull,
			crypto.DigestMD5,
			crypto.DigestSHA1,
			crypto.DigestSHA256,
			crypto.DigestSHA384,
			crypto.DigestSHA512,
			crypto.DigestSM3,
		}

		for _, c := range constants {
			// 只验证常量可以访问
			_ = c
		}
	})

	t.Run("key type constants", func(t *testing.T) {
		constants := []int{
			int(crypto.KeyTypeRSA),
			int(crypto.KeyTypeRSA2),
			int(crypto.KeyTypeEC),
			int(crypto.KeyTypeSM2),
		}

		for _, c := range constants {
			if c == 0 {
				t.Errorf("Key type constant is 0")
			}
		}
	})
}

// TestSM2SignatureAPI 测试SM2签名API
func TestSM2SignatureAPI(t *testing.T) {
	if !tongsuoAvailable() {
		t.Skip("Tongsuo not available")
	}

	t.Run("SignWithOptions is available", func(t *testing.T) {
		key, err := crypto.GenerateECKey(crypto.SM2Curve)
		if err != nil {
			t.Fatalf("Failed to generate SM2 key: %v", err)
		}
		defer key.Wipe()

		// 测试SignWithOptions方法存在
		data := []byte("test message")
		opts := &crypto.SignOptions{
			SM2ID:      "test-id",
			SM2IDIsHex: false,
		}

		signature, err := key.SignWithOptions(crypto.SM3Method(), data, opts)
		if err != nil {
			t.Fatalf("Failed to sign with options: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Empty signature returned")
		}

		t.Logf("SM2 signature length: %d bytes", len(signature))
	})

	t.Run("SignWithOptions with hex ID", func(t *testing.T) {
		key, err := crypto.GenerateECKey(crypto.SM2Curve)
		if err != nil {
			t.Fatalf("Failed to generate SM2 key: %v", err)
		}
		defer key.Wipe()

		hexID := "3132333435363738" // "12345678"的十六进制
		opts := &crypto.SignOptions{
			SM2ID:      hexID,
			SM2IDIsHex: true,
		}

		data := []byte("test message")
		signature, err := key.SignWithOptions(crypto.SM3Method(), data, opts)
		if err != nil {
			t.Fatalf("Failed to sign with hex ID: %v", err)
		}

		if len(signature) == 0 {
			t.Error("Empty signature with hex ID")
		}
	})

	t.Run("SignWithOptions rejects empty ID", func(t *testing.T) {
		key, err := crypto.GenerateECKey(crypto.SM2Curve)
		if err != nil {
			t.Fatalf("Failed to generate SM2 key: %v", err)
		}
		defer key.Wipe()

		opts := &crypto.SignOptions{
			SM2ID:      "",
			SM2IDIsHex: false,
		}

		data := []byte("test message")
		_, err = key.SignWithOptions(crypto.SM3Method(), data, opts)
		if err == nil {
			t.Error("Expected error for empty SM2 ID")
		}
	})
}

// TestMemoryOperations 测试内存操作
func TestMemoryOperations(t *testing.T) {
	t.Run("ZeroBytes is available", func(t *testing.T) {
		data := []byte{1, 2, 3, 4, 5}
		crypto.ZeroBytes(data)

		// 验证数据被清零
		allZero := true
		for _, b := range data {
			if b != 0 {
				allZero = false
				break
			}
		}

		if !allZero {
			t.Error("Data was not zeroed")
		}
	})

	t.Run("ConstantTimeCompare is available", func(t *testing.T) {
		data1 := []byte{1, 2, 3, 4, 5}
		data2 := []byte{1, 2, 3, 4, 5}
		data3 := []byte{1, 2, 3, 4, 6}

		// 相同数据应该返回true
		if !crypto.ConstantTimeCompare(data1, data2) {
			t.Error("ConstantTimeCompare returned false for equal data")
		}

		// 不同数据应该返回false
		if crypto.ConstantTimeCompare(data1, data3) {
			t.Error("ConstantTimeCompare returned true for different data")
		}
	})
}
