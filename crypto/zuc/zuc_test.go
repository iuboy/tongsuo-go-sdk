package zuc_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/zuc"
)

func TestZUC_EncryptDecrypt(t *testing.T) {
	t.Parallel()

	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	plaintext := []byte("Hello ZUC-128-EEA3 stream cipher!")

	ciphertext, err := zuc.Encrypt(key, iv, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if bytes.Equal(ciphertext, plaintext) {
		t.Error("ciphertext should differ from plaintext")
	}

	decrypted, err := zuc.Decrypt(key, iv, ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Errorf("decrypted mismatch\nwant: %x\n got: %x", plaintext, decrypted)
	}
}

func TestZUC_StreamInterface(t *testing.T) {
	t.Parallel()

	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	enc, err := zuc.NewEncrypter(key, iv)
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte("stream cipher test")
	dst := make([]byte, len(msg))
	enc.XORKeyStream(dst, msg)

	dec, err := zuc.NewDecrypter(key, iv)
	if err != nil {
		t.Fatal(err)
	}
	recovered := make([]byte, len(dst))
	dec.XORKeyStream(recovered, dst)

	if !bytes.Equal(recovered, msg) {
		t.Errorf("stream interface mismatch")
	}
}

func TestZUC_EmptyInput(t *testing.T) {
	t.Parallel()

	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	result, err := zuc.Encrypt(key, iv, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("empty input should produce empty output, got %d bytes", len(result))
	}
}

func TestZUC_Deterministic(t *testing.T) {
	t.Parallel()

	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	msg := make([]byte, 256)
	rand.Read(msg)

	ct1, _ := zuc.Encrypt(key, iv, msg)
	ct2, _ := zuc.Encrypt(key, iv, msg)

	if !bytes.Equal(ct1, ct2) {
		t.Error("same key+iv should produce same ciphertext")
	}
}

func TestZUC_DifferentKey(t *testing.T) {
	t.Parallel()

	key1 := make([]byte, zuc.KeySize)
	key2 := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key1)
	rand.Read(key2)
	rand.Read(iv)

	msg := []byte("test data")

	ct1, _ := zuc.Encrypt(key1, iv, msg)
	ct2, _ := zuc.Encrypt(key2, iv, msg)

	if bytes.Equal(ct1, ct2) {
		t.Error("different keys should produce different ciphertext")
	}
}

func TestZUC_InvalidKeySize(t *testing.T) {
	t.Parallel()

	iv := make([]byte, zuc.IVSize)

	_, err := zuc.NewEncrypter([]byte{1, 2, 3}, iv)
	if err == nil {
		t.Error("short key should error")
	}

	_, err = zuc.NewDecrypter([]byte{1, 2, 3}, iv)
	if err == nil {
		t.Error("short key should error")
	}
}

func TestZUC_InvalidIVSize(t *testing.T) {
	t.Parallel()

	key := make([]byte, zuc.KeySize)

	_, err := zuc.NewEncrypter(key, []byte{1, 2, 3})
	if err == nil {
		t.Error("short IV should error")
	}
}

func TestZUC_LargeData(t *testing.T) {
	t.Parallel()

	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	// 64KB test
	data := make([]byte, 65536)
	rand.Read(data)

	ct, err := zuc.Encrypt(key, iv, data)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := zuc.Decrypt(key, iv, ct)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pt, data) {
		t.Error("large data round-trip failed")
	}
}

func BenchmarkZUC_Encrypt_1KB(b *testing.B) {
	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	data := make([]byte, 1024)
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		zuc.Encrypt(key, iv, data)
	}
}

func BenchmarkZUC_Encrypt_8KB(b *testing.B) {
	key := make([]byte, zuc.KeySize)
	iv := make([]byte, zuc.IVSize)
	rand.Read(key)
	rand.Read(iv)

	data := make([]byte, 8192)
	rand.Read(data)

	b.SetBytes(int64(len(data)))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		zuc.Encrypt(key, iv, data)
	}
}
