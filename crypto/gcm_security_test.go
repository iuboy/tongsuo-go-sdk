package crypto_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// newTestGCMSecurityContext 为每个测试创建独立的 GCM 安全上下文，避免全局状态干扰。
func newTestGCMSecurityContext(t *testing.T, maxHistory int) *crypto.GCMSecurityContext {
	t.Helper()
	return crypto.NewGCMSecurityContext(t.Name(), maxHistory)
}

// newTestKey 生成指定长度的随机密钥。
func newTestKey(t *testing.T, size int) []byte {
	t.Helper()
	key, err := crypto.SecureRandomBytes(size)
	if err != nil {
		t.Fatalf("failed to generate %d-byte key: %v", size, err)
	}
	return key
}

// newTestIV 生成指定长度的随机 IV。
func newTestIV(t *testing.T, size int) []byte {
	t.Helper()
	iv, err := crypto.SecureRandomBytes(size)
	if err != nil {
		t.Fatalf("failed to generate %d-byte IV: %v", size, err)
	}
	return iv
}

// ---------------------------------------------------------------------------
// 1. GCMEncrypt / GCMDecrypt round-trip
// ---------------------------------------------------------------------------

func TestGCMEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		keySize   int
		plaintext []byte
		aad       []byte
	}{
		{"AES-256_empty_plaintext_no_aad", 32, []byte{}, nil},
		{"AES-256_hello_no_aad", 32, []byte("hello world"), nil},
		{"AES-256_hello_with_aad", 32, []byte("hello world"), []byte("additional data")},
		{"AES-256_large_payload", 32, make([]byte, 4096), []byte("authenticated header")},
		{"AES-128_key", 16, []byte("128-bit key test"), nil},
		{"AES-192_key", 24, []byte("192-bit key test"), nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := newTestKey(t, tc.keySize)
			iv := newTestIV(t, 12)
			secCtx := newTestGCMSecurityContext(t, 1000)

			ciphertext, tag, err := crypto.GCMEncrypt(key, tc.plaintext, iv, tc.aad, secCtx)
			if err != nil {
				t.Fatalf("GCMEncrypt failed: %v", err)
			}

			if len(ciphertext) != len(tc.plaintext) {
				t.Errorf("ciphertext length %d != plaintext length %d", len(ciphertext), len(tc.plaintext))
			}
			if len(tag) != 16 {
				t.Errorf("tag length %d, expected 16", len(tag))
			}

			plaintext, err := crypto.GCMDecrypt(key, ciphertext, tag, iv, tc.aad, nil)
			if err != nil {
				t.Fatalf("GCMDecrypt failed: %v", err)
			}

			if !bytes.Equal(plaintext, tc.plaintext) {
				t.Errorf("decrypted plaintext mismatch\ngot:  %x\nwant: %x", plaintext, tc.plaintext)
			}
		})
	}
}

// TestGCMDecryptTamperedTag 验证篡改标签后解密失败。
func TestGCMDecryptTamperedTag(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)
	iv := newTestIV(t, 12)
	secCtx := newTestGCMSecurityContext(t, 1000)

	ciphertext, tag, err := crypto.GCMEncrypt(key, []byte("secret"), iv, nil, secCtx)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	// 篡改标签
	tag[len(tag)-1] ^= 0xff

	_, err = crypto.GCMDecrypt(key, ciphertext, tag, iv, nil, nil)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered tag, but succeeded")
	}
}

// TestGCMDecryptTamperedCiphertext 验证篡改密文后解密失败。
func TestGCMDecryptTamperedCiphertext(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)
	iv := newTestIV(t, 12)
	secCtx := newTestGCMSecurityContext(t, 1000)

	ciphertext, tag, err := crypto.GCMEncrypt(key, []byte("important message"), iv, nil, secCtx)
	if err != nil {
		t.Fatalf("GCMEncrypt failed: %v", err)
	}

	if len(ciphertext) == 0 {
		t.Skip("empty ciphertext, cannot tamper")
	}
	ciphertext[0] ^= 0xff

	_, err = crypto.GCMDecrypt(key, ciphertext, tag, iv, nil, nil)
	if err == nil {
		t.Fatal("expected decryption to fail with tampered ciphertext, but succeeded")
	}
}

// ---------------------------------------------------------------------------
// 2. GCMSecurityContext IV reuse detection
// ---------------------------------------------------------------------------

func TestGCMIVReuseDetection(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)
	iv := newTestIV(t, 12)
	secCtx := newTestGCMSecurityContext(t, 1000)

	// 第一次加密应该成功
	_, _, err := crypto.GCMEncrypt(key, []byte("first"), iv, nil, secCtx)
	if err != nil {
		t.Fatalf("first encrypt should succeed: %v", err)
	}

	// 第二次使用相同 IV 必须失败
	_, _, err = crypto.GCMEncrypt(key, []byte("second"), iv, nil, secCtx)
	if err == nil {
		t.Fatal("expected error on IV reuse, but encryption succeeded")
	}
	if !strings.Contains(err.Error(), "reuse") {
		t.Errorf("expected reuse-related error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 3. IV history full
// ---------------------------------------------------------------------------

func TestGCMIVHistoryFull(t *testing.T) {
	t.Parallel()

	const maxHistory = 5
	key := newTestKey(t, 32)
	secCtx := newTestGCMSecurityContext(t, maxHistory)

	// 填满 IV 历史
	for i := 0; i < maxHistory; i++ {
		iv := newTestIV(t, 12)
		_, _, err := crypto.GCMEncrypt(key, []byte("data"), iv, nil, secCtx)
		if err != nil {
			t.Fatalf("encrypt %d should succeed: %v", i, err)
		}
	}

	// 超过限制后必须报错
	iv := newTestIV(t, 12)
	_, _, err := crypto.GCMEncrypt(key, []byte("data"), iv, nil, secCtx)
	if err == nil {
		t.Fatal("expected error when IV history is full, but encryption succeeded")
	}
	if !strings.Contains(err.Error(), "history full") {
		t.Errorf("expected history-full error, got: %v", err)
	}
}

// TestGCMClearIVHistory 验证清空历史后可以继续加密。
func TestGCMClearIVHistory(t *testing.T) {
	t.Parallel()

	const maxHistory = 2
	key := newTestKey(t, 32)
	secCtx := newTestGCMSecurityContext(t, maxHistory)

	// 填满历史
	for i := 0; i < maxHistory; i++ {
		iv := newTestIV(t, 12)
		_, _, err := crypto.GCMEncrypt(key, []byte("data"), iv, nil, secCtx)
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}
	}

	// 下一次应该失败
	iv := newTestIV(t, 12)
	_, _, err := crypto.GCMEncrypt(key, []byte("data"), iv, nil, secCtx)
	if err == nil {
		t.Fatal("expected error when history full")
	}

	// 清空历史
	secCtx.ClearIVHistory()

	// 清空后应该能继续加密
	iv = newTestIV(t, 12)
	_, _, err = crypto.GCMEncrypt(key, []byte("data"), iv, nil, secCtx)
	if err != nil {
		t.Fatalf("expected success after clearing history, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// 4. EncryptWithAutoGCMIV / DecryptWithAutoGCMIV round-trip
// ---------------------------------------------------------------------------

func TestEncryptDecryptWithAutoGCMIV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		keySize   int
		plaintext []byte
		aad       []byte
	}{
		{"AES-256_short", 32, []byte("auto-iv test"), nil},
		{"AES-256_with_aad", 32, []byte("auto-iv with aad"), []byte("header")},
		{"AES-256_empty", 32, []byte{}, nil},
		{"AES-128_key", 16, []byte("128-bit auto-iv"), nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key := newTestKey(t, tc.keySize)
			secCtx := newTestGCMSecurityContext(t, 1000)

			encrypted, err := crypto.EncryptWithAutoGCMIV(key, tc.plaintext, tc.aad, secCtx)
			if err != nil {
				t.Fatalf("EncryptWithAutoGCMIV failed: %v", err)
			}

			// 输出格式: IV(12) + ciphertext + tag(16)
			minLen := 12 + len(tc.plaintext) + 16
			if len(encrypted) < minLen {
				t.Errorf("encrypted length %d, expected at least %d", len(encrypted), minLen)
			}

			plaintext, err := crypto.DecryptWithAutoGCMIV(key, encrypted, tc.aad, nil)
			if err != nil {
				t.Fatalf("DecryptWithAutoGCMIV failed: %v", err)
			}

			if !bytes.Equal(plaintext, tc.plaintext) {
				t.Errorf("decrypted plaintext mismatch\ngot:  %x\nwant: %x", plaintext, tc.plaintext)
			}
		})
	}
}

// TestEncryptWithAutoGCMIVMultiple 同一上下文多次加密应自动生成不同 IV。
func TestEncryptWithAutoGCMIVMultiple(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)
	secCtx := newTestGCMSecurityContext(t, 100)
	plaintext := []byte("repeated encryption")

	// 多次加密应该都成功（每次自动生成新 IV）
	for i := 0; i < 50; i++ {
		encrypted, err := crypto.EncryptWithAutoGCMIV(key, plaintext, nil, secCtx)
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}

		decrypted, err := crypto.DecryptWithAutoGCMIV(key, encrypted, nil, nil)
		if err != nil {
			t.Fatalf("decrypt %d failed: %v", i, err)
		}

		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("round-trip %d: plaintext mismatch", i)
		}
	}
}

// ---------------------------------------------------------------------------
// 5. GenerateGCMRandomIV / GenerateGCMCounterIV basic validation
// ---------------------------------------------------------------------------

func TestGenerateGCMRandomIV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		ivLen  int
		expErr string // 空字符串表示期望成功
	}{
		{"12_bytes", 12, ""},
		{"16_bytes", 16, ""},
		{"64_bytes", 64, ""},
		{"too_short_8", 8, "too short"},
		{"too_short_0", 0, "too short"},
		{"too_large_1025", 1025, "too large"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			iv, err := crypto.GenerateGCMRandomIV(tc.ivLen)
			if tc.expErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.expErr)
				}
				if !strings.Contains(err.Error(), tc.expErr) {
					t.Errorf("error %q should contain %q", err.Error(), tc.expErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(iv) != tc.ivLen {
				t.Errorf("IV length %d, expected %d", len(iv), tc.ivLen)
			}
		})
	}
}

// TestGenerateGCMRandomIVUniqueness 多次生成的 IV 应互不相同。
func TestGenerateGCMRandomIVUniqueness(t *testing.T) {
	t.Parallel()

	const n = 100
	seen := make(map[string]struct{}, n)

	for i := 0; i < n; i++ {
		iv, err := crypto.GenerateGCMRandomIV(12)
		if err != nil {
			t.Fatalf("GenerateGCMRandomIV failed: %v", err)
		}
		key := string(iv)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate IV generated at iteration %d", i)
		}
		seen[key] = struct{}{}
	}
}

func TestGenerateGCMCounterIV(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		baseIV  []byte
		counter uint64
		expErr  string
	}{
		{"valid_12", make([]byte, 12), 1, ""},
		{"valid_16", make([]byte, 16), 42, ""},
		{"valid_large_counter", make([]byte, 12), 0xDEADBEEFCAFE, ""},
		{"too_short_8", make([]byte, 8), 1, "too short"},
		{"too_short_0", []byte{}, 1, "too short"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			iv, err := crypto.GenerateGCMCounterIV(tc.baseIV, tc.counter)
			if tc.expErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.expErr)
				}
				if !strings.Contains(err.Error(), tc.expErr) {
					t.Errorf("error %q should contain %q", err.Error(), tc.expErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(iv) != len(tc.baseIV) {
				t.Errorf("IV length %d, expected %d", len(iv), len(tc.baseIV))
			}
		})
	}
}

// TestGenerateGCMCounterIVSequential 顺序计数器生成的 IV 应互不相同。
func TestGenerateGCMCounterIVSequential(t *testing.T) {
	t.Parallel()

	baseIV := make([]byte, 12)
	seen := make(map[string]struct{}, 50)

	for i := uint64(0); i < 50; i++ {
		iv, err := crypto.GenerateGCMCounterIV(baseIV, i)
		if err != nil {
			t.Fatalf("counter %d: %v", i, err)
		}
		key := string(iv)
		if _, dup := seen[key]; dup {
			t.Fatalf("duplicate counter IV at counter %d", i)
		}
		seen[key] = struct{}{}
	}
}

// ---------------------------------------------------------------------------
// 6. Short IV rejection
// ---------------------------------------------------------------------------

func TestGCMShortIVRejection(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)
	secCtx := newTestGCMSecurityContext(t, 1000)

	shortIVs := []struct {
		name string
		iv   []byte
	}{
		{"empty", []byte{}},
		{"4_bytes", make([]byte, 4)},
		{"8_bytes", make([]byte, 8)},
		{"11_bytes", make([]byte, 11)},
	}

	for _, tc := range shortIVs {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, _, err := crypto.GCMEncrypt(key, []byte("test"), tc.iv, nil, secCtx)
			if err == nil {
				t.Fatal("expected error for short IV, but encryption succeeded")
			}
			if !strings.Contains(err.Error(), "too short") {
				t.Errorf("expected 'too short' error, got: %v", err)
			}
		})
	}
}

// TestGCMDecryptShortIVRejection 解密时短 IV 也应被拒绝。
func TestGCMDecryptShortIVRejection(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)

	_, err := crypto.GCMDecrypt(key, []byte("ciphertext"), make([]byte, 16), make([]byte, 8), nil, nil)
	if err == nil {
		t.Fatal("expected error for short IV in decrypt")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Errorf("expected 'too short' error, got: %v", err)
	}
}

// TestGCMInvalidKeySize 无效密钥长度应被拒绝。
func TestGCMInvalidKeySize(t *testing.T) {
	t.Parallel()

	secCtx := newTestGCMSecurityContext(t, 100)

	invalidKeys := []struct {
		name string
		key  []byte
	}{
		{"8_bytes", make([]byte, 8)},
		{"12_bytes", make([]byte, 12)},
		{"20_bytes", make([]byte, 20)},
		{"64_bytes", make([]byte, 64)},
	}

	for _, tc := range invalidKeys {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			iv := newTestIV(t, 12)
			_, _, err := crypto.GCMEncrypt(tc.key, []byte("test"), iv, nil, secCtx)
			if err == nil {
				t.Fatal("expected error for invalid key size")
			}
			if !strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "key size") {
				t.Errorf("expected key-size error, got: %v", err)
			}
		})
	}
}

// TestGCMInvalidTagSize 解密时无效标签大小应被拒绝。
func TestGCMInvalidTagSize(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)
	iv := newTestIV(t, 12)

	_, err := crypto.GCMDecrypt(key, []byte("ciphertext"), make([]byte, 8), iv, nil, nil)
	if err == nil {
		t.Fatal("expected error for invalid tag size")
	}
	if !strings.Contains(err.Error(), "tag size") {
		t.Errorf("expected tag-size error, got: %v", err)
	}
}

// TestDecryptWithAutoGCMIVDataTooShort 输入数据过短应报错。
func TestDecryptWithAutoGCMIVDataTooShort(t *testing.T) {
	t.Parallel()

	key := newTestKey(t, 32)

	shortData := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"16_bytes", make([]byte, 16)},
		{"27_bytes", make([]byte, 27)}, // 最小 28 (IV 12 + Tag 16)
	}

	for _, tc := range shortData {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			_, err := crypto.DecryptWithAutoGCMIV(key, tc.data, nil, nil)
			if err == nil {
				t.Fatal("expected error for short data")
			}
			if !strings.Contains(err.Error(), "too short") {
				t.Errorf("expected 'too short' error, got: %v", err)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// GetIVHistorySize / GetGCMSecurityContext
// ---------------------------------------------------------------------------

func TestGetIVHistorySize(t *testing.T) {
	t.Parallel()

	secCtx := newTestGCMSecurityContext(t, 100)
	key := newTestKey(t, 32)

	if size := secCtx.GetIVHistorySize(); size != 0 {
		t.Errorf("initial history size should be 0, got %d", size)
	}

	// 执行两次加密
	for i := 0; i < 2; i++ {
		iv := newTestIV(t, 12)
		_, _, err := crypto.GCMEncrypt(key, []byte("data"), iv, nil, secCtx)
		if err != nil {
			t.Fatalf("encrypt %d failed: %v", i, err)
		}
	}

	if size := secCtx.GetIVHistorySize(); size != 2 {
		t.Errorf("history size should be 2, got %d", size)
	}

	secCtx.ClearIVHistory()
	if size := secCtx.GetIVHistorySize(); size != 0 {
		t.Errorf("history size after clear should be 0, got %d", size)
	}
}

func TestGetGCMSecurityContext(t *testing.T) {
	t.Parallel()

	ctx1 := crypto.GetGCMSecurityContext("test-ctx-shared")
	ctx2 := crypto.GetGCMSecurityContext("test-ctx-shared")

	if ctx1 != ctx2 {
		t.Error("GetGCMSecurityContext should return the same instance for the same ID")
	}
}
