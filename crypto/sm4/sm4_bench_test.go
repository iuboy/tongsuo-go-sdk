// SM4 性能基准测试
//
// 覆盖 ECB/CBC/GCM 三种主要模式, 按数据块大小分档
// 运行: go test -bench=BenchmarkSM4 -benchmem ./crypto/sm4/
package sm4_test

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"io"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm4"
)

var benchKey, _ = hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")
var benchIV, _ = hex.DecodeString("0123456789ABCDEFFEDCBA9876543210")

// --- ECB 模式 ---

func benchmarkSM4ECB(b *testing.B, size int) {
	b.Helper()

	plaintext := make([]byte, size)
	io.ReadFull(rand.Reader, plaintext)

	block, err := sm4.NewCipher(benchKey)
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()

	dst := make([]byte, 16)
	for i := 0; i < b.N; i++ {
		for j := 0; j < len(plaintext); j += 16 {
			block.Encrypt(dst, plaintext[j:j+16])
		}
	}
}

func BenchmarkSM4_ECB_16B(b *testing.B)   { benchmarkSM4ECB(b, 16) }
func BenchmarkSM4_ECB_1KB(b *testing.B)   { benchmarkSM4ECB(b, 1024) }
func BenchmarkSM4_ECB_64KB(b *testing.B)  { benchmarkSM4ECB(b, 64*1024) }

// --- CBC 模式 (Go stdlib CBC + SM4 block) ---

func benchmarkSM4CBCEncrypt(b *testing.B, size int) {
	b.Helper()

	plaintext := make([]byte, size)
	io.ReadFull(rand.Reader, plaintext)

	block, err := sm4.NewCipher(benchKey)
	if err != nil {
		b.Fatal(err)
	}

	ciphertext := make([]byte, len(plaintext))
	iv := make([]byte, 16)
	copy(iv, benchIV)

	b.SetBytes(int64(size))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		copy(iv, benchIV)
		stream := cipher.NewCBCEncrypter(block, iv)
		stream.CryptBlocks(ciphertext, plaintext)
	}
}

func BenchmarkSM4_CBC_Encrypt_16B(b *testing.B)   { benchmarkSM4CBCEncrypt(b, 16) }
func BenchmarkSM4_CBC_Encrypt_1KB(b *testing.B)   { benchmarkSM4CBCEncrypt(b, 1024) }
func BenchmarkSM4_CBC_Encrypt_64KB(b *testing.B)  { benchmarkSM4CBCEncrypt(b, 64*1024) }

// --- GCM 模式 ---

func benchmarkSM4GCMSeal(b *testing.B, size int) {
	b.Helper()

	plaintext := make([]byte, size)
	io.ReadFull(rand.Reader, plaintext)

	block, err := sm4.NewCipher(benchKey)
	if err != nil {
		b.Fatal(err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		b.Fatal(err)
	}

	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)

	b.SetBytes(int64(size))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		aead.Seal(nil, iv, plaintext, nil)
	}
}

func BenchmarkSM4_GCM_Seal_16B(b *testing.B)   { benchmarkSM4GCMSeal(b, 16) }
func BenchmarkSM4_GCM_Seal_1KB(b *testing.B)   { benchmarkSM4GCMSeal(b, 1024) }
func BenchmarkSM4_GCM_Seal_64KB(b *testing.B)  { benchmarkSM4GCMSeal(b, 64*1024) }

// --- EVP API 加密 ---

func benchmarkSM4EVPEncrypt(b *testing.B, mode int, size int) {
	b.Helper()

	plaintext := make([]byte, size)
	io.ReadFull(rand.Reader, plaintext)

	b.SetBytes(int64(size))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		enc, err := sm4.NewEncrypter(mode, benchKey, benchIV)
		if err != nil {
			b.Fatal(err)
		}
		enc.SetPadding(false)
		_, err = enc.EncryptAll(plaintext)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM4_EVP_CBC_1KB(b *testing.B) {
	benchmarkSM4EVPEncrypt(b, crypto.CipherModeCBC, 1024)
}

func BenchmarkSM4_EVP_GCM_1KB(b *testing.B) {
	benchmarkSM4EVPEncrypt(b, crypto.CipherModeGCM, 1024)
}
