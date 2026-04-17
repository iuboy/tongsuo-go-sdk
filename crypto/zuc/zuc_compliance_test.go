//go:build compliance

// GM/T 0001-2012 ZUC 祖冲之流密码合规测试
//
// 测试数据来源:
//   - 3GPP TS 35.222: "Specification of the 3GPP Confidentiality and
//     Integrity Algorithms 128-EEA3 & 128-EIA3; Document 3:
//     Implementor's Test Data"
//   - Tongsuo 内部测试: crypto/eia3/eia3.c
//
// 运行: go test -tags=compliance -v ./crypto/zuc/

package zuc_test

import (
	"encoding/hex"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/zuc"
)

// eia3TestCase EIA3 合规测试向量
type eia3TestCase struct {
	name     string
	key      string // 16 字节 hex
	iv       string // 5 字节 hex (COUNT[4] + BEARER+DIR[1])
	input    string // 变长 hex
	expected string // 4 字节 hex MAC
}

// 3GPP TS 35.222 Document 3 Section 3: EIA3 Test Data
var eia3TestVectors = []eia3TestCase{
	{
		name:     "3GPP_EIA3_Test1",
		key:      "00000000000000000000000000000000",
		iv:       "0000000000",
		input:    "00",
		expected: "390a91b7",
	},
	{
		name:     "3GPP_EIA3_Test2",
		key:      "47054125561eb2dda94059da05097850",
		iv:       "561eb2dda0",
		input:    "000000000000000000000000",
		expected: "89a58b47",
	},
	{
		name:     "3GPP_EIA3_Test3",
		key:      "c9e6cec4607c72db000aefa88385ab0a",
		iv:       "a94059da54",
		input: "983b41d47d780c9e1ad11d7eb70391b1" +
			"de0b35da2dc62f83e7b78d6306ca0ea0" +
			"7e941b7be91348f9fcb170e2217fecd9" +
			"7f9f68adb16e5d7d21e569d280ed775c" +
			"ebde3f4093c5388100",
		expected: "24a842b3",
	},
	{
		name:     "3GPP_EIA3_Test4",
		key:      "c8a48262d0c2e2bac4b96ef77e80ca59",
		iv:       "0509785084",
		input: "b546430bf87b4f1ee834704cd6951c36" +
			"e26f108cf731788f48dc34f1678c0522" +
			"1c8fa7ff2f39f477e7e49ef60a4ec2c3" +
			"de24312a96aa26e1cfba57563838b297" +
			"f47e8510c779fd6654b143386fa639d3" +
			"1edbd6c06e47d159d94362f26aeeedee" +
			"0e4f49d9bf8412995415bfad56ee82d1" +
			"ca7463abf085b082b09904d6d990d43c" +
			"f2e062f40839d93248b1eb92cdfed530" +
			"0bc148280430b6d0caa094b6ec8911ab" +
			"7dc36824b824dc0af6682b0935fde7b4" +
			"92a14dc2f43648038da2cf79170d2d50" +
			"133fd49416cb6e33bea90b8bf4559b03" +
			"732a01ea290e6d074f79bb83c10e5800" +
			"15cc1a85b36b5501046e9c4bdcae5135" +
			"690b8666bd54b7a703ea7b6f220a5469" +
			"a568027e",
		expected: "039532e1",
	},
	{
		name:     "3GPP_EIA3_Test5",
		key:      "6b8b08ee79e0b5982d6d128ea9f220cb",
		iv:       "561eb2dde0",
		input: "5bad724710ba1c56d5a315f8d40f6e09" +
			"3780be8e8de07b6992432018e08ed96a" +
			"5734af8bad8a575d3a1f162f85045cc7" +
			"70925571d9f5b94e454a77c16e72936b" +
			"f016ae157499f0543b5d52caa6dbeab6" +
			"97d2bb73e41b8075dce79b4b86044f66" +
			"1d4485a543dd78606e0419e8059859d3" +
			"cb2b67ce0977603f81ff839e33185954" +
			"4cfbc8d00fef1a4c8510fb547d6b06c6" +
			"11ef44f1bce107cfa45a06aab360152b" +
			"28dc1ebe6f7fe09b0516f9a5b02a1bd8" +
			"4bb0181e2e89e19bd8125930d178682f" +
			"3862dc51b636f04e720c47c3ce51ad70" +
			"d94b9b2255fbae906549f499f8c6d399" +
			"47ed5e5df8e2def113253e7b08d0a76b" +
			"6bfc68c812f375c79b8fe5fd85976aa6" +
			"d46b4a2339d8ae5147f680fbe70f978b" +
			"38effd7b2f7866a22554e193a94e98a6" +
			"8b74bd25bb2b3f5fb0a5fd59887f9ab6" +
			"8159b7178d5b7b677cb546bf41eadca2" +
			"16fc10850128f8bdef5c8d89f96afa4f" +
			"a8b54885565ed838a950fee5f1c3b0a4" +
			"f6fb71e54dfd169e82cecc7266c850e6" +
			"7c5ef0ba960f5214060e71eb172a75fc" +
			"1486835cbea6534465b055c96a72e410" +
			"5224182325d830414b40214daa8091d2" +
			"e0fb010ae15c6de90850973bdf1e423b" +
			"e148a237b87a0c9f34d4b47605b803d7" +
			"43a86a90399a4af396d3a1200a62f3d9" +
			"507962e8e5bee6d3da2bb3f7237664ac" +
			"7a292823900bc63503b29e80d63f6067" +
			"bf8e1716ac25beba350deb62a99fe031" +
			"85eb4f69937ecd387941fda544ba67db" +
			"0911774938b01827bcc69c92b3f772a9" +
			"d2859ef003398b1f6bbad7b574f7989a" +
			"1d10b2df798e0dbf30d6587464d24878" +
			"cd00c0eaee8a1a0cc753a27979e11b41" +
			"db1de3d5038afaf49f5c682c3748d8a3" +
			"a9ec54e6a371275f1683510f8e4f9093" +
			"8f9ab6e134c2cfdf4841cba88e0cff2b" +
			"0bcc8e6adcb71109b5198fecf1bb7e5c" +
			"531aca50a56a8a3b6de59862d41fa113" +
			"d9cd957808f08571d9a4bb792af271f6" +
			"cc6dbb8dc7ec36e36be1ed308164c31c" +
			"7c0afc541c",
		expected: "fb9ab74c",
	},
}

func TestCompliance_EIA3(t *testing.T) {
	t.Parallel()

	for _, tc := range eia3TestVectors {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			key, err := hex.DecodeString(tc.key)
			if err != nil {
				t.Fatalf("invalid key hex: %v", err)
			}
			iv, err := hex.DecodeString(tc.iv)
			if err != nil {
				t.Fatalf("invalid IV hex: %v", err)
			}
			input, err := hex.DecodeString(tc.input)
			if err != nil {
				t.Fatalf("invalid input hex: %v", err)
			}
			expectedMAC, err := hex.DecodeString(tc.expected)
			if err != nil {
				t.Fatalf("invalid expected MAC hex: %v", err)
			}

			mac, err := zuc.EIA3MAC(key, iv, input)
			if err != nil {
				t.Fatalf("EIA3MAC: %v", err)
			}

			if len(mac) != zuc.MACSize {
				t.Fatalf("MAC length %d, expected %d", len(mac), zuc.MACSize)
			}

			if !matchMAC(mac, expectedMAC) {
				t.Errorf("MAC mismatch\nname:     %s\ngot:      %x\nexpected: %x",
					tc.name, mac, expectedMAC)
			}
		})
	}
}

// matchMAC 使用常量时间比较 MAC 值
func matchMAC(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
