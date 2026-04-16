//go:build compliance

// GM/T 0004-2012 SM3 密码杂凑算法合规测试
//
// 测试向量来源: GM/T 0004-2012 标准文档附录
// 运行: go test -tags=compliance -v ./crypto/sm3/
// 报告: go test -json -tags=compliance ./crypto/sm3/

package sm3_test

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm3"
)

// gmtSM3Vectors 包含 GM/T 0004-2012 附录中的标准测试向量
//
// 每个测试用例格式: {输入消息(十六进制), 期望的SM3哈希(十六进制)}
// 向量1: 空字符串消息 (0 比特)
// 向量2: "abc" (24 比特) — 最广泛引用的SM3测试向量
// 向量3: 512比特消息 — "abcd"重复16次
var gmtSM3Vectors = []struct {
	name   string
	msgHex string
	expHex string
	bitLen int
}{
	{
		name:   "GM/T0004 向量1: 空消息",
		msgHex: "",
		expHex: "1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b",
		bitLen: 0,
	},
	{
		name:   "GM/T0004 向量2: abc",
		msgHex: "616263",
		expHex: "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0",
		bitLen: 24,
	},
	{
		name:   "GM/T0004 向量3: 512bit消息",
		msgHex: "6162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364616263646162636461626364",
		expHex: "860f7ad118996a6f631c5e4ac693157aefda97a18a873d3323f64c28a8a44fc5",
		bitLen: 512,
	},
}

// TestCompliance_SM3_Sum 验证单次调用 Sum() 对 GM/T 标准向量的正确性
func TestCompliance_SM3_Sum(t *testing.T) {
	t.Parallel()

	for _, tc := range gmtSM3Vectors {
		t.Run(tc.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tc.msgHex)
			expected, _ := hex.DecodeString(tc.expHex)

			got, err := sm3.Sum(msg)
			if err != nil {
				t.Fatalf("Sum() error: %v", err)
			}

			if !bytes.Equal(got[:], expected) {
				t.Errorf("SM3 mismatch\ninput:  %s\nexpect: %x\ngot:    %x",
					tc.msgHex, expected, got)
			}
		})
	}
}

// TestCompliance_SM3_Incremental 验证增量哈希 (Write+Sum) 与单次 Sum 结果一致
//
// 这是 GM/T 0004-2012 的隐含要求: 分块处理和整体处理必须产生相同输出
func TestCompliance_SM3_Incremental(t *testing.T) {
	t.Parallel()

	for _, tc := range gmtSM3Vectors {
		t.Run(tc.name, func(t *testing.T) {
			msg, _ := hex.DecodeString(tc.msgHex)

			// 单次调用
			oneShot, err := sm3.Sum(msg)
			if err != nil {
				t.Fatalf("Sum() error: %v", err)
			}

			// 增量调用: 逐字节写入
			h, err := sm3.New()
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}
			defer h.Close()

			for _, b := range msg {
				h.Write([]byte{b})
			}
			incremental := h.Sum(nil)

			if !bytes.Equal(oneShot[:], incremental) {
				t.Errorf("incremental != one-shot\none-shot:    %x\nincremental: %x",
					oneShot, incremental)
			}
		})
	}
}

// TestCompliance_SM3_BlockSize 验证 SM3 输出和块大小符合 GM/T 0004-2012
func TestCompliance_SM3_BlockSize(t *testing.T) {
	t.Parallel()

	h, err := sm3.New()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// GM/T 0004-2012: SM3 输出 256 比特 (32 字节)
	if h.Size() != 32 {
		t.Errorf("Size() = %d, want 32 (256 bits per GM/T 0004-2012)", h.Size())
	}

	// SM3 压缩函数处理 512 比特 (64 字节) 的消息块
	if h.BlockSize() != 64 {
		t.Errorf("BlockSize() = %d, want 64 (512 bits per GM/T 0004-2012)", h.BlockSize())
	}
}

// TestCompliance_SM3_ResetConsistency 验证 Reset 后哈希状态正确重置
func TestCompliance_SM3_ResetConsistency(t *testing.T) {
	t.Parallel()

	h, err := sm3.New()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	// 先写入一些数据
	h.Write([]byte("garbage data"))
	h.Reset()

	// Reset 后应该和全新实例一样
	msg, _ := hex.DecodeString("616263") // "abc"
	h.Write(msg)
	got := h.Sum(nil)

	expected, _ := hex.DecodeString("66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0")
	if !bytes.Equal(got, expected) {
		t.Errorf("after Reset: got %x, want %x", got, expected)
	}
}

// TestCompliance_SM3_LargeInput 验证大输入的分块处理正确性
//
// 使用 GM/T 向量中的长消息 (多块输入)
func TestCompliance_SM3_LargeInput(t *testing.T) {
	t.Parallel()

	// 来自 GM/T 0004-2012 附录的长消息测试向量
	longInputHex := strings.ReplaceAll(
		`0090414C494345313233405941484F4F2E434F4D787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E49863E4C6`+
			`D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD4`+
			`3D0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A20AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04`+
			`FF4DF2548A7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857`,
		"\n", "")

	input, _ := hex.DecodeString(longInputHex)
	expected, _ := hex.DecodeString("F4A38489E32B45B6F876E3AC2168CA392362DC8F23459C1D1146FC3DBFB7BC9A")

	// 分 3 块写入 (测试多块压缩)
	h, err := sm3.New()
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	chunkSize := len(input) / 3
	for i := 0; i < len(input); i += chunkSize {
		end := i + chunkSize
		if end > len(input) {
			end = len(input)
		}
		h.Write(input[i:end])
	}
	got := h.Sum(nil)

	if !bytes.Equal(got, expected) {
		t.Errorf("large input mismatch\nexpect: %x\ngot:    %x", expected, got)
	}
}
