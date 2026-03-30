#!/bin/bash

# TongSuo Go SDK 8.5 黑盒测试运行脚本
# 用于验证SDK的外部API行为和安全性

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo "TongSuo Go SDK 8.5 黑盒测试套件"
echo "=========================================="
echo ""

# 检查TONGSUO_HOME环境变量
if [ -z "$TONGSUO_HOME" ]; then
    echo -e "${RED}错误: TONGSUO_HOME环境变量未设置${NC}"
    echo "请设置: export TONGSUO_HOME=/opt/tongsuo"
    exit 1
fi

echo "TONGSUO_HOME: $TONGSUO_HOME"

# 检查Tongsuo库是否存在
if [ ! -f "$TONGSUO_HOME/lib/libcrypto.so" ] && [ ! -f "$TONGSUO_HOME/lib/libcrypto.dylib" ]; then
    echo -e "${RED}错误: 找不到Tongsuo库文件${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Tongsuo库检查通过${NC}"
echo ""

# 设置编译和运行环境
if [[ "$OSTYPE" == "darwin"* ]]; then
    export DYLD_LIBRARY_PATH="${TONGSUO_HOME}/lib:${DYLD_LIBRARY_PATH}"
    export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
    export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"
else
    export LD_LIBRARY_PATH="${TONGSUO_HOME}/lib:${LD_LIBRARY_PATH}"
    export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"
    export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"
fi

# 进入测试目录
cd "$(dirname "$0")"

echo "编译环境配置:"
echo "  CGO_CFLAGS=$CGO_CFLAGS"
echo "  CGO_LDFLAGS=$CGO_LDFLAGS"
echo ""

# 运行测试函数
run_test() {
    local test_name="$1"
    local test_args="$2"

    echo "运行测试: $test_name"
    echo "----------------------------------------"

    if go test -v $test_args -timeout 5m; then
        echo -e "${GREEN}✓ $test_name 通过${NC}"
    else
        echo -e "${RED}✗ $test_name 失败${NC}"
        return 1
    fi
    echo ""
}

# 运行所有黑盒测试
echo "=========================================="
echo "运行黑盒测试套件"
echo "=========================================="
echo ""

FAILED_TESTS=0

# 基本API测试
run_test "基本API可用性测试" "-run TestAPIAvailability" || ((FAILED_TESTS++))

# 哈希函数测试
run_test "哈希函数测试" "-run TestHashFunctions" || ((FAILED_TESTS++))

# HMAC测试
run_test "HMAC功能测试" "-run TestHMAC" || ((FAILED_TESTS++))

# 随机数生成测试
run_test "随机数生成测试" "-run TestRandomGeneration" || ((FAILED_TESTS++))

# 密钥生成测试
run_test "密钥生成测试" "-run TestKeyGeneration" || ((FAILED_TESTS++))

# 密钥销毁测试
run_test "密钥销毁测试" "-run TestKeyWipe" || ((FAILED_TESTS++))

# 签名选项测试
run_test "签名选项测试" "-run TestSignOptions" || ((FAILED_TESTS++))

# 错误处理测试
run_test "错误处理测试" "-run TestErrorHandling" || ((FAILED_TESTS++))

# 常量测试
run_test "常量定义测试" "-run TestConstants" || ((FAILED_TESTS++))

# SM2签名API测试
run_test "SM2签名API测试" "-run TestSM2SignatureAPI" || ((FAILED_TESTS++))

# 内存操作测试
run_test "内存操作测试" "-run TestMemoryOperations" || ((FAILED_TESTS++))

# 运行并发测试（可选）
read -p "是否运行并发安全测试？(y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo "运行并发测试..."
    go test -race -v -timeout 5m || echo "并发测试失败"
    echo ""
fi

# 生成测试报告
echo "=========================================="
echo "测试报告"
echo "=========================================="
echo ""

if [ $FAILED_TESTS -eq 0 ]; then
    echo -e "${GREEN}所有测试通过！${NC}"
    echo ""
    echo "测试摘要:"
    echo "  ✓ 基本API可用性"
    echo "  ✓ 哈希函数"
    echo "  ✓ HMAC功能"
    echo "  ✓ 随机数生成"
    echo "  ✓ 密钥生成"
    echo "  ✓ 密钥销毁"
    echo "  ✓ 签名选项"
    echo "  ✓ 错误处理"
    echo "  ✓ 常量定义"
    echo "  ✓ SM2签名API"
    echo "  ✓ 内存操作"
    echo ""
    echo -e "${GREEN}黑盒测试验证完成！${NC}"
    exit 0
else
    echo -e "${RED}有 $FAILED_TESTS 个测试失败${NC}"
    echo ""
    echo "请检查失败的测试并修复问题"
    exit 1
fi
