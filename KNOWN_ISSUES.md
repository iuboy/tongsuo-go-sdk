# 已知问题 (Known Issues)

## RSA 密钥生成崩溃 (Tongsuo 8.5 ARM64)

### 问题描述

在 ARM64 架构上使用 Tongsuo 8.5 进行 RSA 密钥生成时，`EVP_PKEY_CTX_free()` 函数会导致进程崩溃。

### 影响范围

- `crypto.GenerateRSAKey()` 函数
- `crypto.GenerateRSAKeyWithExponent()` 函数
- 所有依赖 RSA 密钥生成的测试

### 根本原因

这是 Tongsuo 8.5 库本身在 ARM64 架构上的问题，不是 Go CGO 代码的问题。通过 C 测试程序验证了该问题：

```c
// C 测试程序也表现出相同的崩溃行为
EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
EVP_PKEY_keygen_init(ctx);
EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
EVP_PKEY_keygen(ctx, &pkey);
EVP_PKEY_free(pkey);
EVP_PKEY_CTX_free(ctx); // ← 此处崩溃
```

### 受影响平台

- macOS ARM64 (Apple Silicon)
- 可能影响其他 ARM64 平台

### 不受影响平台

- x86_64 平台（需验证）

### 临时解决方案

1. 使用预生成的 RSA 密钥
2. 从 PEM 文件加载密钥
3. 使用其他密钥类型（EC、SM2）

### 永久解决方案

等待 Tongsuo 项目修复该问题，或：

1. 向 Tongsuo 项目提交 bug 报告
2. 切换到 x86_64 架构进行 RSA 密钥生成
3. 使用其他密码学库（如 OpenSSL 3.x 官方版本）

### 测试状态

- ✅ SHA1、SHA256、SM3 哈希算法
- ✅ SM2 椭圆曲线密码
- ✅ SM4 对称加密（大部分模式）
- ❌ RSA 密钥生成
- ⚠️ DH 密钥交换（编译问题）

### 报告日期

2026-03-26

### Tongsuo 版本

8.5.0 (基于 OpenSSL 3.5.4)
