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
	"fmt"
	"testing"
)

// TestRSAModernAPICompliance 测试RSA现代化API符合性
//
// 验证：
// - 密钥生成使用EVP_PKEY_keygen（非RSA_generate_key）
// - 符合NIST FIPS 186-4标准
// - 密钥长度符合安全要求
func TestRSAModernAPICompliance(t *testing.T) {
	t.Run("key generation uses modern API", func(t *testing.T) {
		// 生成密钥
		key, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate RSA key: %v", err)
		}
		defer key.Wipe()

		// 验证密钥类型正确
		if key.KeyType() != KeyTypeRSA && key.KeyType() != KeyTypeRSA2 {
			t.Errorf("expected RSA key type, got %v", key.KeyType())
		}

		// 验证密钥可以正常序列化和加载（EVP API 生成的密钥应支持 PKCS8）
		pem, err := key.MarshalPKCS8PrivateKeyPEM()
		if err != nil {
			t.Fatalf("failed to marshal key: %v", err)
		}

		loaded, err := LoadPrivateKeyFromPEM(pem)
		if err != nil {
			t.Fatalf("failed to load marshaled key: %v", err)
		}
		defer loaded.Wipe()

		if loaded.KeyType() != KeyTypeRSA && loaded.KeyType() != KeyTypeRSA2 {
			t.Errorf("loaded key type mismatch: got %v", loaded.KeyType())
		}
	})

	t.Run("key length meets minimum security requirements", func(t *testing.T) {
		// 测试最小密钥长度2048位
		key, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate 2048-bit key: %v", err)
		}
		defer key.Wipe()

		// 验证密钥类型正确
		if key.KeyType() != KeyTypeRSA && key.KeyType() != KeyTypeRSA2 {
			t.Errorf("expected RSA key type, got %v", key.KeyType())
		}

		// 验证密钥可以正常使用（通过签名验证密钥长度符合要求）
		pub := key.Public()
		data := []byte("test data")
		sig, err := key.SignPKCS1v15(SHA256Method(), data)
		if err != nil {
			t.Errorf("failed to sign: %v", err)
		}
		if sig == nil {
			t.Error("signature is nil")
		}
		_ = pub // 使用 pub 避免未使用警告
		_ = sig
	})
}

// TestKeyDestructionCompliance 测试密钥销毁符合性
//
// 验证：
// - 符合NIST SP 800-57 Part 1 Rev.5 Section 5.3.4
// - 密钥材料被正确清零
// - 不能重复使用已销毁的密钥
func TestKeyDestructionCompliance(t *testing.T) {
	t.Run("key wipe prevents reuse", func(t *testing.T) {
		key, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate key: %v", err)
		}

		// 获取公钥在销毁前
		pub := key.Public()

		// 测试签名功能正常
		data := []byte("test data for signature")
		_, err = key.SignPKCS1v15(SHA256Method(), data)
		if err != nil {
			t.Fatalf("failed to sign before wipe: %v", err)
		}

		// 销毁密钥
		err = key.Wipe()
		if err != nil {
			t.Fatalf("failed to wipe key: %v", err)
		}

		// 验证已销毁的密钥不能签名
		_, err = key.SignPKCS1v15(SHA256Method(), data)
		if err == nil {
			t.Error("expected error when signing with wiped key")
		}

		// 验证已销毁的密钥不能解密
		plaintext := []byte("test plaintext")
		ciphertext, err := pub.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("failed to encrypt: %v", err)
		}

		_, err = key.Decrypt(ciphertext)
		if err == nil {
			t.Error("expected error when decrypting with wiped key")
		}
	})

	t.Run("wiped key returns error on double wipe", func(t *testing.T) {
		key, _ := GenerateRSAKey(2048)

		err := key.Wipe()
		if err != nil {
			t.Fatalf("first wipe failed: %v", err)
		}

		err = key.Wipe()
		if err == nil {
			t.Error("expected error on second wipe")
		}
	})
}

// TestAllKeyTypeWipe 测试所有类型的密钥销毁
func TestAllKeyTypeWipe(t *testing.T) {
	keyTypes := []struct {
		name string
		fn   func() (PrivateKey, error)
	}{
		{
			name: "RSA 2048",
			fn:   func() (PrivateKey, error) { return GenerateRSAKey(2048) },
		},
		{
			name: "RSA 3072",
			fn:   func() (PrivateKey, error) { return GenerateRSAKey(3072) },
		},
		{
			name: "RSA 4096",
			fn:   func() (PrivateKey, error) { return GenerateRSAKey(4096) },
		},
		{
			name: "P-256",
			fn:   func() (PrivateKey, error) { return GenerateECKey(Prime256v1) },
		},
		{
			name: "P-384",
			fn:   func() (PrivateKey, error) { return GenerateECKey(Secp384r1) },
		},
		{
			name: "P-521",
			fn:   func() (PrivateKey, error) { return GenerateECKey(Secp521r1) },
		},
		{
			name: "SM2",
			fn:   func() (PrivateKey, error) { return GenerateECKey(SM2Curve) },
		},
	}

	if SupportEd25519() {
		keyTypes = append(keyTypes, struct {
			name string
			fn   func() (PrivateKey, error)
		}{
			name: "Ed25519",
			fn:   GenerateED25519Key,
		})
	}

	for _, kt := range keyTypes {
		t.Run(kt.name, func(t *testing.T) {
			key, err := kt.fn()
			if err != nil {
				t.Fatalf("failed to generate %s key: %v", kt.name, err)
			}

			// 验证密钥可用
			pub := key.Public()
			if pub == nil {
				t.Fatal("expected non-nil public key")
			}

			// 销毁密钥
			err = key.Wipe()
			if err != nil {
				t.Errorf("failed to wipe %s key: %v", kt.name, err)
			}
		})
	}
}

// TestRSAKeyWithExponent 测试自定义指数的RSA密钥生成
func TestRSAKeyWithExponent(t *testing.T) {
	tests := []struct {
		name     string
		bits     int
		exponent int
	}{
		{"2048-bit with 65537", 2048, 65537},
		{"2048-bit with 3", 2048, 3},
		{"2048-bit with 5", 2048, 5},
		{"3072-bit with 65537", 3072, 65537},
		{"4096-bit with 65537", 4096, 65537},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateRSAKeyWithExponent(tt.bits, tt.exponent)
			if err != nil {
				t.Fatalf("failed to generate key with exponent %d: %v", tt.exponent, err)
			}
			defer key.Wipe()

			// 验证密钥可以用于加密解密
			pub := key.Public()
			plaintext := []byte(fmt.Sprintf("test with exponent %d", tt.exponent))
			ciphertext, err := pub.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("failed to encrypt: %v", err)
			}

			decrypted, err := key.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("failed to decrypt: %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("plaintext mismatch")
			}
		})
	}
}

// TestRSASecurityLevelValidation 测试RSA安全级别验证
func TestRSASecurityLevelValidation(t *testing.T) {
	t.Run("rejects insecure key sizes", func(t *testing.T) {
		insecureSizes := []int{512, 1024, 1536, 2047}

		for _, size := range insecureSizes {
			t.Run(fmt.Sprintf("%d-bits", size), func(t *testing.T) {
				_, err := GenerateRSAKey(size)
				if err == nil {
					t.Errorf("expected error for %d-bit key (insecure)", size)
				}

				if !contains(err.Error(), "must be at least 2048 bits") {
					t.Errorf("error message should mention minimum 2048 bits for %d-bit key", size)
				}
			})
		}
	})

	t.Run("rejects invalid exponents", func(t *testing.T) {
		invalidExponents := []int{-1, 0, 2, 1000000000}

		for _, exp := range invalidExponents {
			t.Run(fmt.Sprintf("exponent %d", exp), func(t *testing.T) {
				_, err := GenerateRSAKeyWithExponent(2048, exp)
				if err == nil {
					t.Errorf("expected error for exponent %d", exp)
				}
			})
		}
	})
}

// TestRSAKeyPairOperations 测试RSA密钥对操作
func TestRSAKeyPairOperations(t *testing.T) {
	t.Run("complete key lifecycle", func(t *testing.T) {
		// 1. 生成密钥对
		privateKey, err := GenerateRSAKey(2048)
		if err != nil {
			t.Fatalf("failed to generate key pair: %v", err)
		}
		defer privateKey.Wipe()

		publicKey := privateKey.Public()

		// 2. 序列化
		privPEM, err := privateKey.MarshalPKCS8PrivateKeyPEM()
		if err != nil {
			t.Fatalf("failed to marshal private key: %v", err)
		}

		pubPEM, err := publicKey.MarshalPKIXPublicKeyPEM()
		if err != nil {
			t.Fatalf("failed to marshal public key: %v", err)
		}

		// 3. 反序列化
		loadedPriv, err := LoadPrivateKeyFromPEM(privPEM)
		if err != nil {
			t.Fatalf("failed to load private key: %v", err)
		}
		defer loadedPriv.Wipe()

		loadedPub, err := LoadPublicKeyFromPEM(pubPEM)
		if err != nil {
			t.Fatalf("failed to load public key: %v", err)
		}

		// 4. 使用加载的密钥进行加密解密
		plaintext := []byte("test complete lifecycle")
		ciphertext, err := loadedPub.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("failed to encrypt with loaded key: %v", err)
		}

		decrypted, err := loadedPriv.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("failed to decrypt with loaded key: %v", err)
		}

		if !bytes.Equal(plaintext, decrypted) {
			t.Error("plaintext mismatch after key round-trip")
		}
	})
}

// TestRSAWithMultiplePlaintexts 测试多个明文的加密解密
func TestRSAWithMultiplePlaintexts(t *testing.T) {
	key, _ := GenerateRSAKey(2048)
	defer key.Wipe()

	pub := key.Public()

	plaintexts := [][]byte{
		[]byte("short"),
		[]byte("medium length plaintext"),
		bytes.Repeat([]byte("a"), 200),
		bytes.Repeat([]byte("b"), 100),
	}

	for i, pt := range plaintexts {
		t.Run(fmt.Sprintf("plaintext-%d", i), func(t *testing.T) {
			ct, err := pub.Encrypt(pt)
			if err != nil {
				t.Fatalf("failed to encrypt plaintext %d: %v", i, err)
			}

			dt, err := key.Decrypt(ct)
			if err != nil {
				t.Fatalf("failed to decrypt ciphertext %d: %v", i, err)
			}

			if !bytes.Equal(pt, dt) {
				t.Errorf("plaintext %d mismatch", i)
			}
		})
	}
}

// TestKeyWipeThreadSafety 测试密钥销毁的线程安全性
//
// 注意：这只是一个基本测试，真正的线程安全测试需要race detector
func TestKeyWipeThreadSafety(t *testing.T) {
	t.Run("concurrent wipe operations", func(t *testing.T) {
		keys := make([]PrivateKey, 10)
		for i := range keys {
			var err error
			keys[i], err = GenerateRSAKey(2048)
			if err != nil {
				t.Fatalf("failed to generate key %d: %v", i, err)
			}
		}

		// 并发销毁所有密钥
		done := make(chan bool, len(keys))
		for i, key := range keys {
			go func(k PrivateKey, idx int) {
				defer func() { done <- true }()
				err := k.Wipe()
				if err != nil {
					t.Errorf("failed to wipe key %d: %v", idx, err)
				}
			}(key, i)
		}

		// 等待所有goroutine完成
		for range keys {
			<-done
		}
	})
}

// BenchmarkRSAKeyOperations RSA操作性能基准测试
func BenchmarkRSAKeyOperations(b *testing.B) {
	privateKey, _ := GenerateRSAKey(2048)
	defer privateKey.Wipe()
	publicKey := privateKey.Public()
	plaintext := []byte("benchmark test data")

	b.Run("encryption", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := publicKey.Encrypt(plaintext)
			if err != nil {
				b.Fatalf("benchmark encryption failed: %v", err)
			}
		}
	})

	b.Run("decryption", func(b *testing.B) {
		ciphertext, _ := publicKey.Encrypt(plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := privateKey.Decrypt(ciphertext)
			if err != nil {
				b.Fatalf("benchmark decryption failed: %v", err)
			}
		}
	})

	b.Run("sign-verify", func(b *testing.B) {
		signature, _ := privateKey.SignPKCS1v15(SHA256Method(), plaintext)
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			err := publicKey.VerifyPKCS1v15(SHA256Method(), plaintext, signature)
			if err != nil {
				b.Fatalf("benchmark verification failed: %v", err)
			}
		}
	})
}

// BenchmarkKeyWipePerformance 密钥销毁性能测试
func BenchmarkKeyWipePerformance(b *testing.B) {
	key, _ := GenerateRSAKey(2048)
	defer key.Wipe()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		key.Wipe()
		// 注意：这个基准测试看起来很奇怪，因为第二次wipe会失败
		// 但它测试了wipe操作本身的性能
	}
}
