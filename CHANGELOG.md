## Unreleased

### Breaking Changes

- **`sm3.Sum()`**: 签名从 `func Sum(data []byte) [32]byte` 变更为 `func Sum(data []byte) ([32]byte, error)`。
  新增 error 返回值以报告底层 OpenSSL 错误。
  迁移：`hash := sm3.Sum(data)` → `hash, err := sm3.Sum(data)`

- **`sm3.NewWithEngine()`**: 已移除。Engine 类型整体移除，SM3 不再支持外部 Engine。

- **`crypto.Engine` 类型**: 已移除。Tongsuo 8.5 不再需要显式 Engine 支持。

- **`PublicKey` 接口**: 新增 `VerifyWithOptions(method Method, data, sig []byte, options *SignOptions) error` 方法。
  实现此接口的类型需要添加新方法。

- **`PrivateKey` 接口**: 新增 `SignWithOptions(method Method, data []byte, options *SignOptions) ([]byte, error)` 和 `Wipe() error` 方法。
  实现此接口的类型需要添加新方法。

### New Features

- Support SM2 ECDH key agreement (DeriveSharedSecret, DeriveSharedSecretWithSecurityLevel)
- Support OCSP response creation and parsing (CreateOCSPResponse, ParseOCSPResponse)
- Support CRL creation and parsing
- Support CSR creation and signing
- Support ZUC stream cipher (EEA3/EIA3)
- Support GCM/CCM AEAD encryption with security context (IV reuse detection)
- Support CBC encrypt-then-MAC with HMAC security wrapper
- Support SM4 cipher.Block interface for Go standard library integration
- Support Ed25519 key generation
- Support key wipe (secure key material destruction)
- Support SM2 custom user ID for signing/verification (GM/T 0009-2012)
- Add TLSv1.3 SM cipher suite support

### Bug Fixes

- Fix SM2 signing empty data not validated when method is nil
- Fix GCM IV reuse detection allowing replay after FIFO eviction
- Fix OCSP response creation indentation issues
- Fix gofmt formatting across all source files

### Performance

- Add sync.Pool for SM4 ECB block cipher contexts
- Add named constants for magic numbers (GCM IV/tag lengths, RSA key sizes, etc.)

### Changed

- Tongsuo minimum version raised to 8.3-stable (recommended 8.5+)
- Default Tongsuo library path: /opt/local/tongsuo/ (overridable via CGO_CFLAGS/CGO_LDFLAGS)

## Version 1.0.0 (2025-01-07)

Initial release based on Tongsuo 8.3-stable.

New Features:

- Support hash algorithms: SM3, MD5, SHA1, SHA256
- Support SM4 symmetric encryption algorithm, including CBC/ECB/CFB/OFB/CTR/GCM/CCM mode
- Support SM2 keygen, encryption and decryption
- Support SM2withSM3 digital signature algorithm
- Support HMAC
- Support issuing SM2 certificate
- Support secure transport protocols, including TLCP, TLSv1.0/1.1/1.2/1.3
