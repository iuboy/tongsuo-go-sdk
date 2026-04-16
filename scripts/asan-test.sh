#!/bin/bash
# ASan CGo 内存安全测试
#
# 使用 AddressSanitizer 编译 CGo 代码并运行测试，
# 检测 C 层的内存越界、use-after-free、double-free 等问题。
#
# 用法:
#   ./scripts/asan-test.sh [test-flags]
#
# 注意:
#   - macOS 上 CGo + ASan 可能产生大量误报（系统库未 ASan 编译）
#   - 推荐 Linux 上运行（CI 环境）
#   - ASan 会显著降低性能（2-5x），测试时间会变长

set -euo pipefail

TONGSUO_HOME="${TONGSUO_HOME:-/opt/local/tongsuo}"
CGO_CFLAGS="-fsanitize=address -fno-omit-frame-pointer -I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
CGO_LDFLAGS="-fsanitize=address -L${TONGSUO_HOME}/lib"

# macOS 使用 DYLD_LIBRARY_PATH, Linux 使用 LD_LIBRARY_PATH
if [[ "$(uname)" == "Darwin" ]]; then
    export DYLD_LIBRARY_PATH="${TONGSUO_HOME}/lib:${DYLD_LIBRARY_PATH:-}"
else
    export LD_LIBRARY_PATH="${TONGSUO_HOME}/lib:${LD_LIBRARY_PATH:-}"
fi

export CGO_CFLAGS
export CGO_LDFLAGS
export CGO_ENABLED=1

# ASan 选项:
# detect_leaks=1: 检测内存泄漏
# detect_stack_use_after_return=1: 检测栈上的 use-after-return
# check_initialization_order=1: 检查全局初始化顺序
export ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:halt_on_error=1:print_stats=1"

echo "=== ASan CGo 内存安全测试 ==="
echo "Compiler: $(cc --version 2>&1 | head -1)"
echo "Tongsuo: ${TONGSUO_HOME}"
echo "ASAN_OPTIONS: ${ASAN_OPTIONS}"
echo ""

# 先编译
echo "--- 编译 (ASan enabled) ---"
go build ./... 2>&1 || { echo "BUILD FAILED"; exit 1; }
echo "编译成功"
echo ""

# 运行测试（排除已知问题）
# 注意: 不跑 compliance tag 的测试（太慢）
TEST_FLAGS="${*:- -count=1 -timeout 300s}"

echo "--- 运行测试 ---"
echo "Flags: ${TEST_FLAGS}"
echo ""

# 运行核心 crypto 包测试
echo "=== crypto 包 ==="
go test -v ${TEST_FLAGS} ./crypto/ 2>&1 || true

echo ""
echo "=== crypto 子包 ==="
go test -v ${TEST_FLAGS} ./crypto/sm2/ ./crypto/sm3/ ./crypto/sm4/ ./crypto/zuc/ 2>&1 || true

echo ""
echo "=== 根包 TLS 测试 ==="
go test -v ${TEST_FLAGS} -run "TestTLS13_SM" . 2>&1 || true

echo ""
echo "=== ASan 测试完成 ==="
echo "如果看到 'ERROR: AddressSanitizer' 相关输出，说明检测到内存安全问题。"
