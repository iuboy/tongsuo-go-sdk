// SM3 性能基准测试
//
// 数据块大小分档 (对应 CEO plan Phase 2a):
//   - 小块 (<64B): 16 字节, 测量 CGo 调用开销
//   - 中块 (≥1KB): 1024 字节, 测量有效吞吐量
//   - 大块 (≥1MB): 1048576 字节, 测量极限吞吐量
//
// 运行: go test -bench=BenchmarkSM3 -benchmem ./crypto/sm3/
package sm3_test

import (
	"crypto/rand"
	"io"
	"testing"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto/sm3"
)

func benchSM3(b *testing.B, size int64) {
	b.Helper()

	buf := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		b.Fatal(err)
	}

	b.SetBytes(size)
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		_, err := sm3.Sum(buf)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// 小块: 测量 CGo 固定开销 (~50-200ns)
func BenchmarkSM3_16B(b *testing.B)    { benchSM3(b, 16) }
func BenchmarkSM3_64B(b *testing.B)    { benchSM3(b, 64) }

// 中块: 测量有效吞吐量
func BenchmarkSM3_1KB(b *testing.B)    { benchSM3(b, 1024) }
func BenchmarkSM3_8KB(b *testing.B)    { benchSM3(b, 8*1024) }

// 大块: 测量极限吞吐量
func BenchmarkSM3_1MB(b *testing.B)    { benchSM3(b, 1024*1024) }
func BenchmarkSM3_8MB(b *testing.B)    { benchSM3(b, 8*1024*1024) }

// 增量哈希基准
func benchmarkSM3Incremental(b *testing.B, chunkSize, totalSize int) {
	b.Helper()

	data := make([]byte, totalSize)
	io.ReadFull(rand.Reader, data)

	b.SetBytes(int64(totalSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		h, err := sm3.New()
		if err != nil {
			b.Fatal(err)
		}
		for offset := 0; offset < totalSize; offset += chunkSize {
			end := offset + chunkSize
			if end > totalSize {
				end = totalSize
			}
			h.Write(data[offset:end])
		}
		h.Sum(nil)
		h.Close()
	}
}

func BenchmarkSM3_Incremental_64BChunks_1MB(b *testing.B) {
	benchmarkSM3Incremental(b, 64, 1024*1024)
}

func BenchmarkSM3_Incremental_4KBChunks_1MB(b *testing.B) {
	benchmarkSM3Incremental(b, 4096, 1024*1024)
}
