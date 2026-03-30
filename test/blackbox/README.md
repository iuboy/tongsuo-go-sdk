# TongSuo Go SDK 8.5 黑盒测试套件

## 测试概述

本目录包含TongSuo Go SDK 8.5的黑盒测试用例，专注于验证外部API的行为和安全性，而不依赖内部实现细节。

## 测试原则

1. **外部API验证** - 只测试公开的API接口
2. **输入输出验证** - 验证函数对各种输入的响应
3. **边界条件测试** - 测试极端和边界情况
4. **错误处理测试** - 验证错误情况的处理
5. **安全特性测试** - 验证安全相关功能

## 环境要求

```bash
# 设置Tongsuo环境
export TONGSUO_HOME=/opt/tongsuo

# 验证安装
ls $TONGSUO_HOME/lib/libcrypto.*
```

## 运行测试

```bash
# 运行所有黑盒测试
cd blackbox_tests
go test -v ./...

# 运行特定测试
go test -v -run TestAPIAvailability

# 运行并发测试
go test -race -v ./...
```

## 测试结构

```
blackbox_tests/
├── README.md                 # 本文件
├── test_helper.go           # 测试辅助函数
├── api_availability_test.go # API可用性测试
├── sm2_test.go              # SM2算法测试
├── sm3_test.go              # SM3哈希测试
├── sm4_test.go              # SM4加密测试
├── key_lifecycle_test.go    # 密钥生命周期测试
└── security_test.go         # 安全特性测试
```

## 测试覆盖

- ✅ API可用性验证
- ✅ 基本功能正确性
- ✅ 输入验证
- ✅ 错误处理
- ✅ 边界条件
- ✅ 密钥生命周期
- ✅ 安全特性

## 已知限制

- 需要Tongsuo 8.5库正确安装
- ARM64平台某些测试可能跳过
- 某些测试需要较长执行时间

## 贡献指南

添加新测试时，请遵循以下原则：

1. 只使用公开API
2. 不依赖内部实现
3. 提供清晰的测试描述
4. 包含边界条件
5. 验证错误处理
6. 添加必要的注释
