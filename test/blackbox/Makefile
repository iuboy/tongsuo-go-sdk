# TongSuo Go SDK 8.5 黑盒测试 Makefile

.PHONY: all test test-verbose test-race clean help

# 默认目标
all: test

# 检查TONGSUO_HOME环境变量
check-env:
	@if [ -z "$(TONGSUO_HOME)" ]; then \
		echo "错误: TONGSUO_HOME环境变量未设置"; \
		echo "请设置: export TONGSUO_HOME=/opt/tongsuo"; \
		exit 1; \
	fi
	@echo "TONGSUO_HOME: $(TONGSUO_HOME)"

# 检查Tongsuo库
check-tongsuo: check-env
	@if [ ! -f "$(TONGSUO_HOME)/lib/libcrypto.so" ] && [ ! -f "$(TONGSUO_HOME)/lib/libcrypto.dylib" ]; then \
		echo "错误: 找不到Tongsuo库文件"; \
		exit 1; \
	fi
	@echo "✓ Tongsuo库检查通过"

# 设置CGO环境变量
export-cgo-env:
	@echo "设置CGO编译环境变量..."
	@if [ "$(shell uname)" = "Darwin" ]; then \
		export DYLD_LIBRARY_PATH="${TONGSUO_HOME}/lib:$${DYLD_LIBRARY_PATH}"; \
		export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"; \
		export CGO_LDFLAGS="-L${TONGSUO_HOME}/lib"; \
	else \
		export LD_LIBRARY_PATH="${TONGSUO_HOME}/lib:$${LD_LIBRARY_PATH}"; \
		export CGO_CFLAGS="-I${TONGSUO_HOME}/include -Wno-deprecated-declarations"; \
		export CGO_LDFAGS="-L${TONGSUO_HOME}/lib"; \
	fi

# 运行所有黑盒测试
test: check-tongsuo export-cgo-env
	@echo "=========================================="
	@echo "运行黑盒测试套件"
	@echo "=========================================="
	@echo ""
	go test -v ./...

# 详细输出测试
test-verbose: check-tongsuo export-cgo-env
	@echo "运行详细黑盒测试..."
	go test -v -cover ./...

# 并发安全测试
test-race: check-tongsuo export-cgo-env
	@echo "运行并发安全测试（包含race detector）..."
	go test -race -v ./...

# 运行特定测试
test-hash: check-tongsuo export-cgo-env
	@echo "运行哈希函数测试..."
	go test -v -run TestHashFunctions ./...

test-hmac: check-tongsuo export-cgo-env
	@echo "运行HMAC测试..."
	go test -v -run TestHMAC ./...

test-key: check-tongsuo export-cgo-env
	@echo "运行密钥管理测试..."
	go test -v -run "TestKeyGeneration|TestKeyWipe" ./...

test-sm2: check-tongsuo export-cgo-env
	@echo "运行SM2签名测试..."
	go test -v -run TestSM2SignatureAPI ./...

# 清理测试文件
clean:
	@echo "清理测试文件..."
	rm -f coverage.out coverage.html
	@echo "✓ 清理完成"

# 运行测试并生成覆盖率报告
coverage: check-tongsuo export-cgo-env
	@echo "运行测试并生成覆盖率报告..."
	go test -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "覆盖率报告已生成: coverage.html"

# 查看测试环境信息
env-info:
	@echo "=========================================="
	@echo "测试环境信息"
	@echo "=========================================="
	@echo "Go版本: $$(go version)"
	@echo "操作系统: $$(uname -s)"
	@echo "架构: $$(uname -m)"
	@echo "TONGSUO_HOME: $${TONGSUO_HOME:-未设置}"
	@if [ -n "$$TONGSUO_HOME" ]; then \
		echo "Tongsuo版本: $$($$TONGSUO_HOME/bin/openssl version 2>/dev/null || echo '未知')"; \
	fi

# 帮助信息
help:
	@echo "TongSuo Go SDK 8.5 黑盒测试 - 可用命令："
	@echo ""
	@echo "测试命令："
	@echo "  make test                - 运行所有黑盒测试"
	@echo "  make test-verbose         - 详细输出测试"
	@echo "  make test-race            - 并发安全测试（含race detector）"
	@echo ""
	@echo "特定测试："
	@echo "  make test-hash            - 哈希函数测试"
	@echo "  make test-hmac            - HMAC测试"
	@echo "  make test-key             - 密钥管理测试"
	@echo "  make test-sm2             - SM2签名测试"
	@echo ""
	@echo "覆盖率："
	@echo "  make coverage             - 生成覆盖率报告"
	@echo ""
	@echo "其他："
	@echo "  make clean                - 清理测试文件"
	@echo "  make env-info             - 查看测试环境信息"
	@echo ""
	@echo "环境要求："
	@echo "  - 设置 TONGSUO_HOME 环境变量"
	@echo "  - 安装 Tongsuo 8.5 或更高版本"
	@echo "  - 安装 Go 1.16 或更高版本"
