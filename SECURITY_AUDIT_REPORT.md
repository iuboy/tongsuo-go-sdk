# TongSuo Go SDK 8.5 密码学安全审查报告

**审查日期**: 2026-03-26
**审查人员**: 密码学安全专家
**项目版本**: TongSuo 8.5.0 (基于 OpenSSL 3.5.4)
**审查范围**: 完整密码学实现、密钥管理、加密算法、协议实现

---

## 执行摘要

本次审查对 TongSuo Go SDK 8.5 进行了全面的密码学安全评估。该SDK实现了国产密码算法（SM2、SM3、SM4）以及国际标准算法。

### 总体安全评级: **良好 (B+)**

**优点:**
- 密钥生成使用现代EVP API，符合FIPS 186-4标准
- 实现了密钥销毁机制（Wipe）
- GCM模式有IV重用检测
- 提供CBC模式的填充oracle攻击防护
- SM2签名符合GM/T 0009-2012标准
- 使用密码学安全的随机数生成器

**需要改进的问题:**
- 1个严重问题 (SM2签名密钥泄露风险)
- 3个高优先级问题
- 5个中优先级问题
- 若干低优先级建议

---

## 1. 密钥管理安全

### 1.1 密钥生成 ✅ (符合标准)

**文件**: `crypto/key.go`

**优点:**
- RSA密钥生成使用`EVP_PKEY_keygen` API（而非废弃的`RSA_generate_key`）
- 最小密钥长度强制为2048位，符合NIST SP 800-57 Part 1 Rev.5
- 公共指数验证（奇数、≥3、防止过大指数）
- SM2密钥直接使用`EVP_PKEY_SM2`类型生成

**代码示例:**
```go
// 符合 FIPS 186-4 的密钥生成
keyCtx := C.X_EVP_PKEY_CTX_new_id(C.EVP_PKEY_RSA, nil)
C.X_EVP_PKEY_keygen_init(keyCtx)
C.X_EVP_PKEY_CTX_set_rsa_keygen_bits(keyCtx, C.int(bits))
```

### 1.2 密钥销毁 ⚠️ (部分符合)

**文件**: `crypto/key.go:343-356`

**优点:**
- 提供了`Wipe()`方法用于密钥销毁
- 符合NIST SP 800-57 Part 1 Rev.5 Section 5.3.4

**问题:**
```go
// 问题: 密钥销毁后，指针设为nil，但finalizer仍然存在
func (key *pKey) Wipe() error {
    if key.key == nil {
        return fmt.Errorf("key already wiped or nil")
    }
    C.X_EVP_PKEY_free(key.key)
    key.key = nil  // 指针清零，但finalizer未移除
    return nil
}
```

**建议:**
```go
// 应该移除finalizer，防止双重释放
runtime.SetFinalizer(key, nil)
```

### 1.3 密钥存储和传输 ⚠️ (需注意)

**问题:**
1. **密钥泄露风险** - 在多处代码中，密钥被直接从Go byte切片传递到C代码：
   ```go
   // crypto/key.go:55
   if C.X_HMAC_Init_ex(hmac.ctx, unsafe.Pointer(&key[0]), C.int(len(key)), md, nil) != 1
   ```

   **风险**: Go的垃圾回收器可能会移动内存，导致悬空指针。

2. **SM2签名ID硬编码**:
   ```go
   // crypto/key.go:203
   sm2DefaultID := "1234567812345678"  // 固定的用户ID
   ```

   **风险**: 固定ID可能不适合所有应用场景

---

## 2. 加密模式安全

### 2.1 GCM模式 ✅ (良好)

**文件**: `crypto/gcm_security.go`

**优点:**
- 实现了IV重用检测机制
- 强制最小IV长度为12字节（NIST推荐）
- 提供自动IV生成功能

```go
// IV重用检测
func (ctx *GCMSecurityContext) checkAndRecordIV(iv []byte) error {
    if len(iv) < 12 {
        return fmt.Errorf("IV too short")
    }
    ivStr := hex.EncodeToString(iv)
    if ctx.ivHistory[ivStr] {
        return fmt.Errorf("GCM IV reuse detected - critical security failure!")
    }
    ctx.ivHistory[ivStr] = true
    return nil
}
```

**问题:**
- IV历史存储在内存map中，可能导致内存泄漏
- 没有持久化机制，重启后历史丢失

### 2.2 CBC模式 ⚠️ (有防护)

**文件**: `crypto/cbc_security.go`

**优点:**
- 提供填充oracle攻击防护
- 实现Encrypt-then-MAC模式
- 提供常量时间填充验证

**问题:**
- CBC模式仍然可被直接使用，没有强制使用安全包装器
- 错误消息可能泄露信息：
  ```go
  // crypto/cbc_security.go:74
  return nil, fmt.Errorf("decryption failed")  // 统一错误消息好
  ```

### 2.3 ECB模式 ❌ (默认禁用 - 好)

**文件**: `crypto/sm4/sm4.go:95-110`

**优点:**
- ECB模式默认禁用
- 需要显式设置环境变量才能使用
- 提供详细的安全警告

```go
if !allowUnsafeModes {
    return nil, fmt.Errorf("ECB mode is insecure and disabled by default\n\n" +
        "Security Risks:\n" +
        "- ECB mode does not hide plaintext patterns\n" +
        ...
    )
}
```

---

## 3. SM2实现安全

### 3.1 SM2签名 ⚠️ (有密钥泄露风险)

**文件**: `crypto/key.go:184-221`

**严重问题 - 密钥泄露:**

```go
// crypto/key.go:204
sm2ID := C.CString(sm2DefaultID)
defer C.X_free(unsafe.Pointer(sm2ID))

// 问题: 在调用EVP_PKEY_CTX_set1_id之前，私钥已经被加载到上下文
// 如果sm2ID被泄露，攻击者可能获得签名密钥的线索
```

**建议:**
1. SM2 ID应该由调用者提供，而非硬编码
2. 使用后应立即清零敏感数据

### 3.2 SM2加密 ✅ (标准实现)

**文件**: `crypto/sm2/sm2.go`

**优点:**
- 符合GM/T 0009-2012标准
- 正确使用EVP API
- 类型检查严格

---

## 4. SM4实现安全

### 4.1 加密模式 ⚠️ (依赖调用者)

**文件**: `crypto/sm4/sm4.go`

**优点:**
- 支持多种模式（ECB/CBC/CFB/OFB/CTR/GCM/CCM）
- ECB模式默认禁用
- GCM/CCM模式提供AEAD功能

**问题:**
- 调用者可选择任何模式，包括不安全的ECB
- 没有强制使用GCM等安全模式

### 4.2 密钥长度验证 ✅

```go
const (
    BlockSize = 16
    KeySize   = 16  // 固定128位密钥
)

func NewCipher(key []byte) (cipher.Block, error) {
    if len(key) != KeySize {
        return nil, fmt.Errorf("invalid key size: %w", crypto.ErrInvalidKeySize)
    }
    ...
}
```

---

## 5. 密钥派生和DH

### 5.1 DH密钥交换 ⚠️ (KDF可选)

**文件**: `crypto/dh.go`

**优点:**
- 实现了公钥验证（小subgroup攻击防护）
- 支持KDF密钥派生
- 符合NIST SP 800-56A标准

**问题:**
- KDF默认启用但可被禁用：
  ```go
  func DefaultDHKDFConfig() *DHKDFConfig {
      return &DHKDFConfig{
          UseKDF: true,  // 默认启用
          ...
      }
  }
  ```

  **风险**: 如果禁用KDF，原始共享秘密直接使用，不安全

### 5.2 密钥派生函数 ✅

**优点:**
- 支持HKDF（RFC 5869）
- 支持TLS 1.3 HKDF格式
- 支持盐值和上下文信息绑定

---

## 6. 随机数生成

### 6.1 随机数质量 ✅ (优秀)

**文件**: `crypto/secure.go`

**优点:**
- 使用`crypto/rand`而非`math/rand`
- 符合NIST SP 800-90A要求
- 提供多种安全随机函数

```go
func SecureRandomBytes(length int) ([]byte, error) {
    buf := make([]byte, length)
    _, err := rand.Read(buf)  // crypto/rand - CSPRNG
    ...
}
```

### 6.2 素数生成 ⚠️ (使用Go标准库)

**文件**: `crypto/secure.go:313-365`

**优点:**
- 实现了安全素数生成
- 支持可配置的Miller-Rabin测试轮数

**问题:**
- 依赖Go的`rand.Prime`，默认测试轮数为20
- 对于高安全性应用，可能需要更多轮数

---

## 7. HMAC和消息认证

### 7.1 HMAC实现 ✅ (良好)

**文件**: `crypto/hmac.go`

**优点:**
- 密钥长度验证
- 使用常量时间比较
- 正确使用EVP API

```go
func (h *HMAC) Verify(expected []byte) error {
    actual, err := h.Final()
    if err != nil {
        return err
    }
    if !ConstantTimeCompare(actual, expected) {  // 常量时间比较
        return fmt.Errorf("HMAC verification failed")
    }
    return nil
}
```

---

## 8. 时序攻击防护

### 8.1 常量时间比较 ✅ (优秀)

**文件**: `crypto/secure.go`

**优点:**
- 提供多个常量时间比较函数
- 使用Go标准库的`subtle.ConstantTimeCompare`

```go
func ConstantTimeCompare(a, b []byte) bool {
    return subtle.ConstantTimeCompare(a, b) == 1
}

func VerifyMAC(expected, actual []byte) error {
    if !ConstantTimeCompare(expected, actual) {
        return fmt.Errorf("MAC verification failed")
    }
    return nil
}
```

### 8.2 延迟验证 ✅

```go
func DelayVerification() {
    const minDelay = 100 * time.Millisecond  // NIST SP 800-63B建议
    time.Sleep(minDelay)
}
```

---

## 9. 已知问题

**文件**: `KNOWN_ISSUES.md`

### 9.1 ARM64平台RSA密钥生成崩溃 ❌ (严重)

**问题描述:**
- 在ARM64架构上，`EVP_PKEY_CTX_free()`导致进程崩溃
- 影响所有RSA密钥生成操作

**影响:**
- macOS ARM64 (Apple Silicon)
- 可能影响其他ARM64平台

**临时解决方案:**
1. 使用预生成的RSA密钥
2. 使用其他密钥类型（EC、SM2）
3. 切换到x86_64架构

---

## 10. 侧信道攻击防护

### 10.1 内存清零 ⚠️ (有限保护)

**文件**: `crypto/secure.go`

**优点:**
- 提供`ZeroBytes`和`WipeBytes`函数

**问题:**
- Go的垃圾回收器可能复制内存
- 不能保证所有副本都被清零

```go
func ZeroBytes(b []byte) {
    for i := range b {
        b[i] = 0  // 可能被编译器优化掉
    }
}
```

**建议:**
- 使用`runtime.KeepAlive`防止优化
- 考虑使用专门的内存清零库

### 10.2 缓存时序攻击 ⚠️ (未明确防护)

- 未发现明显的缓存时序攻击防护措施
- GCM IV检测使用map，可能存在时序泄露

---

## 11. 错误处理和信息泄露

### 11.1 错误消息 ⚠️ (混合)

**好的例子:**
```go
// crypto/cbc_security.go:74
return nil, fmt.Errorf("decryption failed")  // 模糊错误
```

**需要改进:**
```go
// crypto/key.go:666
return nil, fmt.Errorf("RSA key size must be at least 2048 bits")
// 过于详细，可能泄露系统配置信息
```

---

## 12. 测试覆盖

**文件**: `crypto/key_compliance_test.go`

### 12.1 密钥销毁测试 ✅

```go
func TestKeyDestructionCompliance(t *testing.T) {
    t.Run("key wipe prevents reuse", func(t *testing.T) {
        key, _ := GenerateRSAKey(2048)
        key.Wipe()
        _, err := key.SignPKCS1v15(SHA256Method(), data)
        if err == nil {
            t.Error("expected error when signing with wiped key")
        }
    })
}
```

### 12.2 安全级别验证测试 ✅

```go
func TestRSASecurityLevelValidation(t *testing.T) {
    t.Run("rejects insecure key sizes", func(t *testing.T) {
        insecureSizes := []int{512, 1024, 1536, 2047}
        for _, size := range insecureSizes {
            _, err := GenerateRSAKey(size)
            if err == nil {
                t.Errorf("expected error for %d-bit key", size)
            }
        }
    })
}
```

---

## 13. 依赖项安全

### 13.1 TongSuo 8.5 ✅

- 基于OpenSSL 3.5.4
- FIPS 140-2验证可用
- 国密算法认证

### 13.2 Go标准库 ✅

- `crypto/rand` - CSPRNG
- `crypto/subtle` - 常量时间操作
- `crypto/cipher` - 加密接口

---

## 14. 合规性评估

### 14.1 国际标准

| 标准 | 符合程度 | 说明 |
|------|---------|------|
| NIST SP 800-57 Part 1 Rev.5 | ✅ 符合 | 密钥管理 |
| NIST SP 800-38A | ⚠️ 部分符合 | 加密模式 |
| NIST SP 800-38D | ✅ 符合 | GCM模式 |
| NIST SP 800-56A | ⚠️ 部分符合 | DH密钥交换 |
| NIST SP 800-56C | ⚠️ 部分符合 | KDF |
| FIPS 186-4 | ✅ 符合 | 数字签名 |
| FIPS 140-2 | ✅ 符合 | 密码模块 |

### 14.2 国密标准

| 标准 | 符合程度 | 说明 |
|------|---------|------|
| GM/T 0009-2012 | ✅ 符合 | SM2签名 |
| GB/T 32918-2017 | ✅ 符合 | SM2椭圆曲线 |
| GB/T 3624-2018 | ⚠️ 部分符合 | SM2使用规范 |
| GM/T 0022-2014 | ✅ 符合 | SM4 |
| GM/T 0004-2012 | ✅ 符合 | SM3 |
| GB/T 39786-2021 | ⚠️ 部分符合 | 密码应用基本要求 |

---

## 15. 风险汇总

### 15.1 严重风险 (1项)

1. **SM2签名固定ID泄露风险** (`crypto/key.go:203`)
   - 固定的SM2用户ID可能泄露签名密钥信息
   - **建议**: 让调用者提供SM2 ID

### 15.2 高优先级风险 (3项)

1. **密钥销毁后finalizer未移除** (`crypto/key.go:343-356`)
   - 可能导致双重释放或use-after-free
   - **建议**: 在Wipe()中移除finalizer

2. **KDF可被禁用** (`crypto/dh.go`)
   - 禁用KDF后使用原始共享秘密不安全
   - **建议**: 强制启用KDF或至少警告

3. **CBC模式错误处理** (`crypto/cbc_security.go`)
   - DecryptFinal错误可能泄露填充信息
   - **建议**: 统一使用常量时间错误处理

### 15.3 中优先级风险 (5项)

1. **IV历史内存管理** (`crypto/gcm_security.go`)
   - IV历史无限增长可能导致内存耗尽
   - **建议**: 实现自动清理和大小限制

2. **Go-Cgo边界密钥传递**
   - 密钥可能被Go GC移动
   - **建议**: 使用runtime.KeepAlive

3. **错误消息过于详细**
   - 可能泄露系统配置
   - **建议**: 生产环境使用模糊错误

4. **内存清零不彻底** (`crypto/secure.go`)
   - 可能被编译器优化
   - **建议**: 使用专门的内存清零技术

5. **测试覆盖不完整**
   - 缺少并发测试
   - **建议**: 添加race detector测试

### 15.4 低优先级建议 (若干项)

1. 添加侧信道攻击防护测试
2. 实现密钥版本管理
3. 添加密码学强度的性能基准测试
4. 提供更详细的API文档和安全指南

---

## 16. 建议措施

### 16.1 立即行动 (严重问题)

1. **修复SM2签名ID问题**:
   ```go
   // 建议的API
   func SignWithSM2ID(priv PrivateKey, data []byte, sm2ID string) ([]byte, error)
   ```

2. **修复密钥销毁**:
   ```go
   func (key *pKey) Wipe() error {
       if key.key == nil {
           return fmt.Errorf("key already wiped")
       }
       C.X_EVP_PKEY_free(key.key)
       key.key = nil
       runtime.SetFinalizer(key, nil)  // 添加这行
       return nil
   }
   ```

### 16.2 短期改进 (1-3个月)

1. 强制启用KDF或至少警告
2. 实现IV历史自动清理
3. 添加runtime.KeepAlive保护
4. 统一错误消息处理

### 16.3 长期改进 (3-12个月)

1. 实现完整的侧信道攻击防护
2. 添加FIPS模式（严格限制算法使用）
3. 实现密钥托管和备份机制
4. 提供密码学安全审计日志

---

## 17. 结论

TongSuo Go SDK 8.5 在密码学安全方面表现**良好**，主要算法实现符合国际和国密标准。项目团队对安全性有明确意识，实现了多项安全防护措施。

**主要优点:**
- 使用现代EVP API
- 密钥生成符合FIPS标准
- 提供密钥销毁机制
- GCM模式有IV重用检测
- 国密算法实现规范

**主要不足:**
- SM2签名固定ID问题
- 密钥销毁实现不完整
- 某些安全防护是可选的
- 侧信道攻击防护有限

**总体建议:**
该SDK适合在生产环境中使用，但建议在部署前修复严重和高优先级问题。对于高安全性应用，建议进行额外的安全审查和渗透测试。

---

## 附录A: 审查方法

本次审查采用了以下方法：
1. 静态代码分析
2. 密码学最佳实践对比
3. 国密和国际标准符合性检查
4. 常见密码学攻击模式检查
5. 侧信道攻击风险评估

## 附录B: 参考资料

1. NIST SP 800-57 Part 1 Rev.5 - Key Management
2. NIST SP 800-38A - Recommendation for Block Cipher Modes
3. NIST SP 800-38D - GCM and GMAC
4. NIST SP 800-56A - Key Establishment
5. FIPS 186-4 - Digital Signature Standard
6. GM/T 0009-2012 - SM2密码密码算法使用规范
7. GB/T 39786-2021 - 信息安全技术 信息系统密码应用基本要求
8. RFC 5116 - AEAD
9. RFC 5869 - HKDF
10. RFC 8446 - TLS 1.3

---

**审查人员签名**: 密码学安全专家
**审查日期**: 2026-03-26
**报告版本**: 1.0
**下次审查建议**: 2026-09-26 或重大版本更新时
