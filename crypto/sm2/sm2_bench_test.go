// SM2 性能基准测试
//
// 覆盖: 密钥生成, 签名/验签, 加密/解密
// 运行: go test -bench=BenchmarkSM2 -benchmem ./crypto/sm2/
package sm2_test

import (
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm2"
)

func BenchmarkSM2_GenerateKey(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2.GenerateKey()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM2_SignASN1(b *testing.B) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("benchmark message for SM2 signing performance measurement")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2.SignASN1(priv, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM2_VerifyASN1(b *testing.B) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.Public()

	data := []byte("benchmark message for SM2 signing performance measurement")
	sig, err := sm2.SignASN1(priv, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := sm2.VerifyASN1(pub, data, sig)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM2_Encrypt(b *testing.B) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.Public()

	data := []byte("benchmark message for SM2 encryption performance test, 64 bytes padding here!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2.Encrypt(pub, data)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSM2_Decrypt(b *testing.B) {
	priv, err := sm2.GenerateKey()
	if err != nil {
		b.Fatal(err)
	}
	pub := priv.Public()

	data := []byte("benchmark message for SM2 encryption performance test, 64 bytes padding here!")
	ciphertext, err := sm2.Encrypt(pub, data)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sm2.Decrypt(priv, ciphertext)
		if err != nil {
			b.Fatal(err)
		}
	}
}
