package crypto_test

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

// newTestCBCSafeWrapper creates a CBCSafeWrapper for testing purposes.
func newTestCBCSafeWrapper(t *testing.T) *crypto.CBCSafeWrapper {
	t.Helper()

	cipher, err := crypto.GetCipherByName("aes-256-cbc")
	if err != nil {
		t.Fatalf("GetCipherByName failed: %v", err)
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("generate key: %v", err)
	}

	wrapper, err := crypto.NewCBCSafeWrapper(cipher, key, nil, crypto.DigestSHA256)
	if err != nil {
		t.Fatalf("NewCBCSafeWrapper failed: %v", err)
	}

	return wrapper
}

// ============================================================================
// CBCSafeWrapper Seal/Open round-trip
// ============================================================================

func TestCBCSafeWrapper_SealOpenRoundTrip(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte("hello tongsuo cbc security wrapper")
	sealed, err := wrapper.Seal(plaintext, nil, nil)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	got, err := wrapper.Open(sealed, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %x, want %x", got, plaintext)
	}
}

func TestCBCSafeWrapper_SealOpenWithAAD(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte("authenticated data test")
	aad := []byte("associated data for authentication")

	sealed, err := wrapper.Seal(plaintext, nil, aad)
	if err != nil {
		t.Fatalf("Seal with AAD failed: %v", err)
	}

	// Open with matching AAD should succeed.
	got, err := wrapper.Open(sealed, aad)
	if err != nil {
		t.Fatalf("Open with matching AAD failed: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %x, want %x", got, plaintext)
	}

	// Open with wrong AAD should fail.
	_, err = wrapper.Open(sealed, []byte("wrong aad"))
	if err == nil {
		t.Fatal("expected error when opening with wrong AAD, got nil")
	}
}

func TestCBCSafeWrapper_SealOpenWithNonce(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte("fixed nonce test")
	nonce := make([]byte, 16) // AES-256-CBC IV size
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	sealed, err := wrapper.Seal(plaintext, nonce, nil)
	if err != nil {
		t.Fatalf("Seal with nonce failed: %v", err)
	}

	got, err := wrapper.Open(sealed, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Errorf("round-trip mismatch: got %x, want %x", got, plaintext)
	}
}

func TestCBCSafeWrapper_SealOpenEmptyPlaintext(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte{}

	sealed, err := wrapper.Seal(plaintext, nil, nil)
	if err != nil {
		t.Fatalf("Seal empty plaintext failed: %v", err)
	}

	got, err := wrapper.Open(sealed, nil)
	if err != nil {
		t.Fatalf("Open empty plaintext failed: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("expected empty plaintext, got %x", got)
	}
}

// ============================================================================
// Tampered ciphertext must fail on Open
// ============================================================================

func TestCBCSafeWrapper_TamperedCiphertext(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte("tamper detection test data")
	sealed, err := wrapper.Seal(plaintext, nil, nil)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Flip a byte in the ciphertext region (between IV and tag).
	ivSize := 16
	tagSize := 32 // SHA-256 HMAC tag
	if len(sealed) <= ivSize+tagSize {
		t.Fatal("sealed data too short to tamper ciphertext")
	}

	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[ivSize+1] ^= 0xFF // flip a byte in ciphertext area

	_, err = wrapper.Open(tampered, nil)
	if err == nil {
		t.Fatal("expected error when opening tampered ciphertext, got nil")
	}
}

// ============================================================================
// Tampered MAC tag must fail on Open
// ============================================================================

func TestCBCSafeWrapper_TamperedTag(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte("tag tamper detection")
	sealed, err := wrapper.Seal(plaintext, nil, nil)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Flip the last byte (in the MAC tag region).
	tampered := make([]byte, len(sealed))
	copy(tampered, sealed)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = wrapper.Open(tampered, nil)
	if err == nil {
		t.Fatal("expected error when opening with tampered tag, got nil")
	}
}

func TestCBCSafeWrapper_TruncatedData(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	plaintext := []byte("truncation test")
	sealed, err := wrapper.Seal(plaintext, nil, nil)
	if err != nil {
		t.Fatalf("Seal failed: %v", err)
	}

	// Severely truncated data should fail.
	_, err = wrapper.Open(sealed[:5], nil)
	if err == nil {
		t.Fatal("expected error when opening truncated data, got nil")
	}
}

// ============================================================================
// PKCS7 padding edge cases
// ============================================================================

func TestAddPKCS7Padding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		blockSize int
		wantLen   int // expected length of padded output
		wantPad   byte
	}{
		{
			name:      "exact block boundary adds full block",
			data:      bytes.Repeat([]byte{0xAA}, 16),
			blockSize: 16,
			wantLen:   32,
			wantPad:   16,
		},
		{
			name:      "one byte short adds single byte padding",
			data:      bytes.Repeat([]byte{0xAA}, 15),
			blockSize: 16,
			wantLen:   16,
			wantPad:   1,
		},
		{
			name:      "empty data adds full block padding",
			data:      []byte{},
			blockSize: 16,
			wantLen:   16,
			wantPad:   16,
		},
		{
			name:      "two bytes short adds two byte padding",
			data:      bytes.Repeat([]byte{0xAA}, 14),
			blockSize: 16,
			wantLen:   16,
			wantPad:   2,
		},
		{
			name:      "large block size 32",
			data:      bytes.Repeat([]byte{0xBB}, 24),
			blockSize: 32,
			wantLen:   32,
			wantPad:   8,
		},
		{
			name:      "block size 1",
			data:      []byte{0xCC},
			blockSize: 1,
			wantLen:   2,
			wantPad:   1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			padded, err := crypto.AddPKCS7Padding(tt.data, tt.blockSize)
			if err != nil {
				t.Fatalf("AddPKCS7Padding failed: %v", err)
			}
			if len(padded) != tt.wantLen {
				t.Errorf("padded length = %d, want %d", len(padded), tt.wantLen)
			}
			if len(padded) > 0 && padded[len(padded)-1] != tt.wantPad {
				t.Errorf("last padding byte = %d, want %d", padded[len(padded)-1], tt.wantPad)
			}
			// Verify all padding bytes are correct.
			padLen := int(tt.wantPad)
			for i := len(padded) - padLen; i < len(padded); i++ {
				if padded[i] != tt.wantPad {
					t.Errorf("padding byte at index %d = %d, want %d", i, padded[i], tt.wantPad)
				}
			}
		})
	}
}

func TestAddPKCS7Padding_InvalidBlockSize(t *testing.T) {
	t.Parallel()

	_, err := crypto.AddPKCS7Padding([]byte{1, 2, 3}, 0)
	if err == nil {
		t.Fatal("expected error for block size 0, got nil")
	}

	_, err = crypto.AddPKCS7Padding([]byte{1, 2, 3}, 257)
	if err == nil {
		t.Fatal("expected error for block size 257, got nil")
	}
}

// ============================================================================
// ValidatePKCS7Padding and RemovePKCS7Padding edge cases
// ============================================================================

func TestValidatePKCS7Padding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		blockSize int
		wantErr   bool
	}{
		{
			name:      "valid padding single byte",
			data:      append(bytes.Repeat([]byte{0xAA}, 15), 0x01),
			blockSize: 16,
			wantErr:   false,
		},
		{
			name:      "valid padding full block of 16",
			data:      append(bytes.Repeat([]byte{0xAA}, 16), bytes.Repeat([]byte{0x10}, 16)...),
			blockSize: 16,
			wantErr:   false,
		},
		{
			name:      "valid padding two bytes",
			data:      append(bytes.Repeat([]byte{0xAA}, 14), 0x02, 0x02),
			blockSize: 16,
			wantErr:   false,
		},
		{
			name:      "invalid padding byte zero",
			data:      append(bytes.Repeat([]byte{0xAA}, 15), 0x00),
			blockSize: 16,
			wantErr:   true,
		},
		{
			name:      "invalid padding byte exceeds block size",
			data:      append(bytes.Repeat([]byte{0xAA}, 15), 0x11), // 17 > 16
			blockSize: 16,
			wantErr:   true,
		},
		{
			name:      "invalid inconsistent padding bytes",
			data:      append(bytes.Repeat([]byte{0xAA}, 14), 0x03, 0x02),
			blockSize: 16,
			wantErr:   true,
		},
		{
			name:      "empty data returns error",
			data:      []byte{},
			blockSize: 16,
			wantErr:   true,
		},
		{
			name:      "single byte valid padding for block size 1",
			data:      []byte{0x01},
			blockSize: 1,
			wantErr:   false,
		},
		{
			name:      "padding length larger than data length",
			data:      []byte{0x05, 0x05},
			blockSize: 16,
			wantErr:   true,
		},
		{
			name:      "invalid block size 0",
			data:      []byte{0x01},
			blockSize: 0,
			wantErr:   true,
		},
		{
			name:      "invalid block size 257",
			data:      []byte{0x01},
			blockSize: 257,
			wantErr:   true,
		},
		{
			name:      "valid padding 15 bytes in 16-byte block",
			data:      append([]byte{0xAA}, bytes.Repeat([]byte{0x0F}, 15)...),
			blockSize: 16,
			wantErr:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := crypto.ValidatePKCS7Padding(tt.data, tt.blockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePKCS7Padding() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRemovePKCS7Padding(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		blockSize int
		wantData  []byte
		wantErr   bool
	}{
		{
			name:      "remove single byte padding",
			data:      append(bytes.Repeat([]byte{0xAA}, 15), 0x01),
			blockSize: 16,
			wantData:  bytes.Repeat([]byte{0xAA}, 15),
			wantErr:   false,
		},
		{
			name:      "remove full block padding",
			data:      append(bytes.Repeat([]byte{0xAA}, 16), bytes.Repeat([]byte{0x10}, 16)...),
			blockSize: 16,
			wantData:  bytes.Repeat([]byte{0xAA}, 16),
			wantErr:   false,
		},
		{
			name:      "remove two byte padding",
			data:      append(bytes.Repeat([]byte{0xAA}, 14), 0x02, 0x02),
			blockSize: 16,
			wantData:  bytes.Repeat([]byte{0xAA}, 14),
			wantErr:   false,
		},
		{
			name:      "invalid padding returns error",
			data:      append(bytes.Repeat([]byte{0xAA}, 15), 0x00),
			blockSize: 16,
			wantData:  nil,
			wantErr:   true,
		},
		{
			name:      "empty data returns error",
			data:      []byte{},
			blockSize: 16,
			wantData:  nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := crypto.RemovePKCS7Padding(tt.data, tt.blockSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("RemovePKCS7Padding() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.wantData) {
				t.Errorf("RemovePKCS7Padding() = %x, want %x", got, tt.wantData)
			}
		})
	}
}

func TestAddRemovePKCS7Padding_RoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      []byte
		blockSize int
	}{
		{name: "empty", data: []byte{}, blockSize: 16},
		{name: "1 byte", data: []byte{0x01}, blockSize: 16},
		{name: "15 bytes", data: bytes.Repeat([]byte{0xAA}, 15), blockSize: 16},
		{name: "exact block", data: bytes.Repeat([]byte{0xBB}, 16), blockSize: 16},
		{name: "17 bytes", data: bytes.Repeat([]byte{0xCC}, 17), blockSize: 16},
		{name: "100 bytes", data: bytes.Repeat([]byte{0xDD}, 100), blockSize: 16},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			padded, err := crypto.AddPKCS7Padding(tt.data, tt.blockSize)
			if err != nil {
				t.Fatalf("AddPKCS7Padding failed: %v", err)
			}

			unpadded, err := crypto.RemovePKCS7Padding(padded, tt.blockSize)
			if err != nil {
				t.Fatalf("RemovePKCS7Padding failed: %v", err)
			}

			if !bytes.Equal(unpadded, tt.data) {
				t.Errorf("round-trip mismatch: got %x, want %x", unpadded, tt.data)
			}
		})
	}
}

// ============================================================================
// CheckPaddingOracleVulnerability
// ============================================================================

func TestCheckPaddingOracleVulnerability(t *testing.T) {
	t.Parallel()

	results := crypto.CheckPaddingOracleVulnerability()
	if results == nil {
		t.Fatal("CheckPaddingOracleVulnerability returned nil")
	}

	// Verify required keys exist.
	requiredKeys := []string{
		"constant_time_padding",
		"encrypt_then_mac",
		"generic_errors",
		"hmac_verification",
		"risk_score",
		"risk_level",
	}
	for _, key := range requiredKeys {
		if _, ok := results[key]; !ok {
			t.Errorf("missing key in results: %s", key)
		}
	}

	// Risk level must be one of the valid values.
	riskLevel, ok := results["risk_level"].(string)
	if !ok {
		t.Fatal("risk_level is not a string")
	}
	validLevels := map[string]bool{"HIGH": true, "MEDIUM": true, "LOW": true, "NONE": true}
	if !validLevels[riskLevel] {
		t.Errorf("unexpected risk_level: %s", riskLevel)
	}

	// Risk score must be non-negative.
	riskScore, ok := results["risk_score"].(int)
	if !ok {
		t.Fatal("risk_score is not an int")
	}
	if riskScore < 0 {
		t.Errorf("risk_score should be non-negative, got %d", riskScore)
	}

	// hmac_verification should be true (the package has HMAC support).
	hmacVerification, ok := results["hmac_verification"].(bool)
	if !ok {
		t.Fatal("hmac_verification is not a bool")
	}
	if !hmacVerification {
		t.Error("hmac_verification should be true; the package provides HMAC")
	}
}

// ============================================================================
// NewCBCSafeWrapper input validation
// ============================================================================

func TestNewCBCSafeWrapper_NilCipher(t *testing.T) {
	t.Parallel()

	key := make([]byte, 32)
	_, err := crypto.NewCBCSafeWrapper(nil, key, nil, crypto.DigestSHA256)
	if err == nil {
		t.Fatal("expected error for nil cipher, got nil")
	}
}

func TestNewCBCSafeWrapper_NilKey(t *testing.T) {
	t.Parallel()

	cipher, err := crypto.GetCipherByName("aes-256-cbc")
	if err != nil {
		t.Fatalf("GetCipherByName failed: %v", err)
	}

	_, err = crypto.NewCBCSafeWrapper(cipher, nil, nil, crypto.DigestSHA256)
	if err == nil {
		t.Fatal("expected error for nil key, got nil")
	}
}

func TestNewCBCSafeWrapper_CustomHMACKey(t *testing.T) {
	t.Parallel()

	cipher, err := crypto.GetCipherByName("aes-256-cbc")
	if err != nil {
		t.Fatalf("GetCipherByName failed: %v", err)
	}

	encKey := make([]byte, 32)
	if _, err := rand.Read(encKey); err != nil {
		t.Fatalf("generate enc key: %v", err)
	}
	hmacKey := make([]byte, 32)
	if _, err := rand.Read(hmacKey); err != nil {
		t.Fatalf("generate hmac key: %v", err)
	}

	wrapper, err := crypto.NewCBCSafeWrapper(cipher, encKey, hmacKey, crypto.DigestSHA256)
	if err != nil {
		t.Fatalf("NewCBCSafeWrapper with custom HMAC key failed: %v", err)
	}

	// Verify the HMAC key is accessible and matches.
	gotKey := wrapper.GetHMACKey()
	if !bytes.Equal(gotKey, hmacKey) {
		t.Error("GetHMACKey returned key that does not match the custom HMAC key")
	}

	// Verify defensive copy: modifying returned slice should not affect internal state.
	gotKey[0] ^= 0xFF
	gotKey2 := wrapper.GetHMACKey()
	if !bytes.Equal(gotKey2, hmacKey) {
		t.Error("GetHMACKey defensive copy violated: internal state was affected by external mutation")
	}
}

// ============================================================================
// MigrateCBCToAEAD
// ============================================================================

func TestMigrateCBCToAEAD(t *testing.T) {
	t.Parallel()

	result := crypto.MigrateCBCToAEAD()
	if result == nil {
		t.Fatal("MigrateCBCToAEAD returned nil")
	}

	expectedSteps := []string{"step_1", "step_2", "step_3", "step_4", "step_5", "step_6", "note"}
	for _, key := range expectedSteps {
		if _, ok := result[key]; !ok {
			t.Errorf("missing key in migration steps: %s", key)
		}
	}
}

// ============================================================================
// CBCSecureDecrypt integration (via CBCSafeWrapper)
// ============================================================================

func TestCBCSafeWrapper_MultipleRoundTrips(t *testing.T) {
	t.Parallel()

	wrapper := newTestCBCSafeWrapper(t)

	messages := [][]byte{
		[]byte("short"),
		[]byte("exactly sixteen"), // 16 bytes = 1 AES block
		[]byte("this is a longer message that spans multiple AES blocks for testing"),
		bytes.Repeat([]byte{0x42}, 1),
		bytes.Repeat([]byte{0x42}, 15),
		bytes.Repeat([]byte{0x42}, 16),
		bytes.Repeat([]byte{0x42}, 17),
		bytes.Repeat([]byte{0x42}, 31),
		bytes.Repeat([]byte{0x42}, 32),
		bytes.Repeat([]byte{0x42}, 33),
	}

	for i, msg := range messages {
		sealed, err := wrapper.Seal(msg, nil, nil)
		if err != nil {
			t.Fatalf("Seal message %d failed: %v", i, err)
		}

		got, err := wrapper.Open(sealed, nil)
		if err != nil {
			t.Fatalf("Open message %d failed: %v", i, err)
		}

		if !bytes.Equal(got, msg) {
			t.Errorf("message %d: round-trip mismatch (len=%d vs %d)", i, len(got), len(msg))
		}
	}
}
