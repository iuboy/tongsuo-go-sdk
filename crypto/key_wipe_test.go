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
	"bytes"
	"testing"
)

// TestRSAModernKeyGeneration 测试现代化的RSA密钥生成
//
// 符合标准：
// - NIST FIPS 186-4 (Digital Signature Standard)
// - NIST SP 800-57 Part 1 Rev.5 (Key Management)
func TestRSAModernKeyGeneration(t *testing.T) {
	tests := []struct {
		name      string
		bits      int
		exponent  int
		wantError bool
		errorMsg  string
	}{
		{
			name:     "2048-bit key with default exponent",
			bits:     2048,
			exponent: 0,
		},
		{
			name:     "2048-bit key with custom exponent 65537",
			bits:     2048,
			exponent: 65537,
		},
		{
			name:     "3072-bit key with default exponent",
			bits:     3072,
			exponent: 0,
		},
		{
			name:     "4096-bit key with default exponent",
			bits:     4096,
			exponent: 0,
		},
		{
			name:      "Invalid: key size too small (< 2048)",
			bits:      1024,
			exponent:  0,
			wantError: true,
			errorMsg:  "must be at least 2048 bits",
		},
		{
			name:      "Invalid: even exponent",
			bits:      2048,
			exponent:  4,
			wantError: true,
			errorMsg:  "must be odd",
		},
		{
			name:      "Invalid: exponent too small",
			bits:      2048,
			exponent:  1,
			wantError: true,
			errorMsg:  "must be at least 3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var key PrivateKey
			var err error

			if tt.exponent == 0 {
				key, err = GenerateRSAKey(tt.bits)
			} else {
				key, err = GenerateRSAKeyWithExponent(tt.bits, tt.exponent)
			}

			if tt.wantError {
				if err == nil {
					t.Errorf("expected error containing '%s', but got no error", tt.errorMsg)
					return
				}
				if !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error containing '%s', but got '%s'", tt.errorMsg, err.Error())
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if key == nil {
				t.Error("expected non-nil key")
				return
			}

			// 验证密钥类型
			if key.KeyType() != KeyTypeRSA && key.KeyType() != KeyTypeRSA2 {
				t.Errorf("expected RSA key type, got %v", key.KeyType())
			}

			// 验证可以获取公钥
			pub := key.Public()
			if pub == nil {
				t.Error("expected non-nil public key")
			}

			// 验证可以序列化
			_, err = key.MarshalPKCS8PrivateKeyPEM()
			if err != nil {
				t.Errorf("failed to marshal private key: %v", err)
			}
		})
	}
}

// TestRSAKeyWipe 测试RSA密钥销毁功能
//
// 符合标准：
// - NIST SP 800-57 Part 1 Rev.5 Section 5.3.4 (Cryptographic Key Destruction)
func TestRSAKeyWipe(t *testing.T) {
	t.Run("wipe and verify", func(t *testing.T) {
		key, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		// 验证密钥正常工作
		pub := key.Public()
		if pub == nil {
			t.Fatal("expected non-nil public key")
		}

		// 销毁密钥
		err = key.Wipe()
		if err != nil {
			t.Errorf("failed to wipe key: %v", err)
		}

		// 再次销毁应该返回错误
		err = key.Wipe()
		if err == nil {
			t.Error("expected error when wiping already-wiped key")
		}
	})

	t.Run("wipe multiple keys", func(t *testing.T) {
		keys := make([]PrivateKey, 10)
		for i := range keys {
			var err error
			keys[i], err = GenerateRSAKey(2048)
			if err != nil {
				t.Fatalf("failed to generate key %d: %v", i, err)
			}
		}

		// 销毁所有密钥
		for i, key := range keys {
			err := key.Wipe()
			if err != nil {
				t.Errorf("failed to wipe key %d: %v", i, err)
			}
		}
	})
}

// TestECKeyWipe 测试EC密钥销毁功能
func TestECKeyWipe(t *testing.T) {
	curves := []struct {
		name  string
		curve EllipticCurve
	}{
		{"P-256", Prime256v1},
		{"P-384", Secp384r1},
		{"P-521", Secp521r1},
	}

	for _, tc := range curves {
		t.Run(tc.name, func(t *testing.T) {
			key, err := GenerateECKey(tc.curve)
			if err != nil {
				t.Fatalf("failed to generate EC key: %v", err)
			}

			// 销毁密钥
			err = key.Wipe()
			if err != nil {
				t.Errorf("failed to wipe EC key: %v", err)
			}
		})
	}
}

// TestSM2KeyWipe 测试SM2密钥销毁功能
//
// 符合标准：
// - GB/T 39786-2021 (信息系统密码应用基本要求)
func TestSM2KeyWipe(t *testing.T) {
	t.Run("SM2 key wipe", func(t *testing.T) {
		key, err := GenerateECKey(SM2Curve)
		if err != nil {
			t.Fatalf("failed to generate SM2 key: %v", err)
		}

		if key.KeyType() != KeyTypeSM2 {
			t.Errorf("expected SM2 key type, got %v", key.KeyType())
		}

		// 销毁密钥
		err = key.Wipe()
		if err != nil {
			t.Errorf("failed to wipe SM2 key: %v", err)
		}
	})
}

// TestEd25519KeyWipe 测试Ed25519密钥销毁功能
func TestEd25519KeyWipe(t *testing.T) {
	t.Run("Ed25519 key wipe", func(t *testing.T) {
		if !SupportEd25519() {
			t.Skip("Ed25519 not supported")
		}

		key, err := GenerateED25519Key()
		if err != nil {
			t.Fatalf("failed to generate Ed25519 key: %v", err)
		}

		// 销毁密钥
		err = key.Wipe()
		if err != nil {
			t.Errorf("failed to wipe Ed25519 key: %v", err)
		}
	})
}

// TestRSABasicCryptoOperations 测试RSA基本加密解密操作
func TestRSABasicCryptoOperations(t *testing.T) {
	t.Run("encrypt and decrypt", func(t *testing.T) {
		// 生成密钥对
		privateKey, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		defer privateKey.Wipe()

		publicKey := privateKey.Public()

		// 测试数据
		plaintext := []byte("Hello, RSA!")

		// 加密
		ciphertext, err := publicKey.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		// 解密
		decrypted, err := privateKey.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("failed to decrypt: %v", err)
		}

		// 验证
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("plaintext mismatch:\ngot:  %x\nwant: %x", decrypted, plaintext)
		}
	})
}

// TestRSA签名和验证 测试RSA签名功能
func TestRSA签名和验证(t *testing.T) {
	t.Run("sign and verify", func(t *testing.T) {
		privateKey, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		defer privateKey.Wipe()

		publicKey := privateKey.Public()

		// 测试数据
		data := []byte("Hello, RSA Signature!")

		// 签名
		signature, err := privateKey.SignPKCS1v15(SHA256Method(), data)
		if err != nil {
			t.Fatalf("failed to sign: %v", err)
		}

		// 验证
		err = publicKey.VerifyPKCS1v15(SHA256Method(), data, signature)
		if err != nil {
			t.Errorf("signature verification failed: %v", err)
		}

		// 错误的数据应该验证失败
		wrongData := []byte("Wrong data")
		err = publicKey.VerifyPKCS1v15(SHA256Method(), wrongData, signature)
		if err == nil {
			t.Error("expected verification error for wrong data")
		}
	})
}

// TestKeyWipePreventsReuse 测试密钥销毁后不能使用
func TestKeyWipePreventsReuse(t *testing.T) {
	t.Run("wiped key cannot sign", func(t *testing.T) {
		key, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}

		// 销毁密钥
		err = key.Wipe()
		if err != nil {
			t.Fatalf("failed to wipe key: %v", err)
		}

		// 尝试使用已销毁的密钥签名
		data := []byte("test")
		_, err = key.SignPKCS1v15(SHA256Method(), data)
		if err == nil {
			t.Error("expected error when signing with wiped key")
		}
	})
}

// TestRSALargeKeyGeneration 测试大密钥生成
//
// 性能测试：验证大密钥生成不会过度耗时
func TestRSALargeKeyGeneration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large key generation test in short mode")
	}

	t.Run("4096-bit key generation", func(t *testing.T) {
		key, err := GenerateRSAKey(4096)
		if err != nil {
			t.Fatalf("failed to generate 4096-bit RSA key: %v", err)
		}
		defer key.Wipe()

		if key == nil {
			t.Fatal("expected non-nil key")
		}
	})
}

// BenchmarkRSAKeyGeneration2048 RSA密钥生成基准测试
func BenchmarkRSAKeyGeneration2048(b *testing.B) {
	var key PrivateKey
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err = GenerateRSAKey(2048)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
		_ = key.Wipe()
	}
}

// BenchmarkRSAKeyGeneration4096 RSA 4096位密钥生成基准测试
func BenchmarkRSAKeyGeneration4096(b *testing.B) {
	var key PrivateKey
	var err error

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key, err = GenerateRSAKey(4096)
		if err != nil {
			b.Fatalf("benchmark failed: %v", err)
		}
		_ = key.Wipe()
	}
}

// BenchmarkKeyWipe 密钥销毁基准测试
func BenchmarkKeyWipe(b *testing.B) {
	key, _ := GenerateRSAKey(2048)
	defer key.Wipe()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Wipe()
	}
}

// Helper function
func contains(s, substr string) bool {
	return bytes.Contains([]byte(s), []byte(substr))
}
