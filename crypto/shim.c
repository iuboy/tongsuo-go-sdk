// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <string.h>

#include <openssl/conf.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/ocsp.h>

#include "_cgo_export.h"

/*
 * Functions defined in other .c files
 * OpenSSL 3.x: 线程安全回调已废弃，不再需要
 */
// extern int go_init_locks();
// extern void go_thread_locking_callback(int, int, const char*, int);
// extern unsigned long go_thread_id_callback();
static int go_write_bio_puts(BIO *b, const char *str) {
	return go_write_bio_write(b, (char*)str, (int)strlen(str));
}

const EVP_MD *X_EVP_sm3() {
	return EVP_sm3();
}

const int X_ED25519_SUPPORT = 1;
int X_EVP_PKEY_ED25519 = EVP_PKEY_ED25519;

int X_EVP_Digest(const void *data, size_t count,
		unsigned char *md, unsigned int *size,
		const EVP_MD *type, ENGINE *impl){
	return EVP_Digest(data, count, md, size, type, impl);
}

int X_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
		const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
	return EVP_DigestSignInit(ctx, pctx, type, e, pkey);
}

int X_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	return EVP_DigestSignUpdate(ctx, d, cnt);
}

int X_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen)
{
	return EVP_DigestSignFinal(ctx, sig, siglen);
}

int X_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret,
		size_t *siglen, const unsigned char *tbs, size_t tbslen) {
	return EVP_DigestSign(ctx, sigret, siglen, tbs, tbslen);
}


int X_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx,
		const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey)
{
	return EVP_DigestVerifyInit(ctx, pctx, type, e, pkey);
}

int X_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt)
{
	return EVP_DigestVerifyUpdate(ctx, d, cnt);
}

int X_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen)
{
	return EVP_DigestVerifyFinal(ctx, sig, siglen);
}

int X_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret,
		size_t siglen, const unsigned char *tbs, size_t tbslen){
	return EVP_DigestVerify(ctx, sigret, siglen, tbs, tbslen);
}

void X_BIO_set_data(BIO* bio, void* data) {
	BIO_set_data(bio, data);
}

void* X_BIO_get_data(BIO* bio) {
	return BIO_get_data(bio);
}

long X_BIO_get_mem_data(BIO *b, char **pp) {
    return BIO_get_mem_data(b, pp);
}

EVP_MD_CTX* X_EVP_MD_CTX_new() {
	return EVP_MD_CTX_new();
}

int X_EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in) {
	return EVP_MD_CTX_copy_ex(out, in);
}

void X_EVP_MD_CTX_free(EVP_MD_CTX* ctx) {
	EVP_MD_CTX_free(ctx);
}

static int x_bio_create(BIO *b) {
	BIO_set_shutdown(b, 1);
	BIO_set_init(b, 1);
	BIO_set_data(b, NULL);
	BIO_clear_flags(b, ~0);
	return 1;
}

static int x_bio_free(BIO *b) {
	(void)b;
	return 1;
}

static BIO_METHOD *writeBioMethod;
static BIO_METHOD *readBioMethod;

BIO_METHOD* BIO_s_readBio() { return readBioMethod; }
BIO_METHOD* BIO_s_writeBio() { return writeBioMethod; }

int x_bio_init_methods() {
	writeBioMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Go Write BIO");
	if (!writeBioMethod) {
		return 1;
	}
	if (1 != BIO_meth_set_write(writeBioMethod,
				(int (*)(BIO *, const char *, int))go_write_bio_write)) {
		return 2;
	}
	if (1 != BIO_meth_set_puts(writeBioMethod, go_write_bio_puts)) {
		return 3;
	}
	if (1 != BIO_meth_set_ctrl(writeBioMethod, go_write_bio_ctrl)) {
		return 4;
	}
	if (1 != BIO_meth_set_create(writeBioMethod, x_bio_create)) {
		return 5;
	}
	if (1 != BIO_meth_set_destroy(writeBioMethod, x_bio_free)) {
		return 6;
	}

	readBioMethod = BIO_meth_new(BIO_TYPE_SOURCE_SINK, "Go Read BIO");
	if (!readBioMethod) {
		return 7;
	}
	if (1 != BIO_meth_set_read(readBioMethod, go_read_bio_read)) {
		return 8;
	}
	if (1 != BIO_meth_set_ctrl(readBioMethod, go_read_bio_ctrl)) {
		return 9;
	}
	if (1 != BIO_meth_set_create(readBioMethod, x_bio_create)) {
		return 10;
	}
	if (1 != BIO_meth_set_destroy(readBioMethod, x_bio_free)) {
		return 11;
	}

	return 0;
}

const EVP_MD *X_EVP_dss() {
	return NULL;
}

const EVP_MD *X_EVP_dss1() {
	return NULL;
}

const EVP_MD *X_EVP_sha() {
	return NULL;
}

int X_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx) {
	return EVP_CIPHER_CTX_encrypting(ctx);
}

EVP_CIPHER_CTX *X_EVP_CIPHER_CTX_new() {
	return EVP_CIPHER_CTX_new();
}

void X_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx) {
	EVP_CIPHER_CTX_free(ctx);
}

int X_EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx) {
	return EVP_CIPHER_CTX_reset(ctx);
}

const EVP_CIPHER *X_EVP_sm4_ecb() {
	return EVP_sm4_ecb();
}

int X_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
	return EVP_EncryptInit_ex(ctx, cipher, impl, key, iv);
}

int X_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
	return EVP_EncryptUpdate(ctx, out, outl, in, inl);
}

int X_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
	return EVP_EncryptFinal_ex(ctx, out, outl);
}

int X_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv) {
	return EVP_DecryptInit_ex(ctx, cipher, impl, key, iv);
}

int X_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl) {
	return EVP_DecryptUpdate(ctx, out, outl, in, inl);
}

int X_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl) {
	return EVP_DecryptFinal_ex(ctx, out, outl);
}

int X_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits) {
	return EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits);
}

int X_EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp) {
	return EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, pubexp);
}

EVP_PKEY_CTX *X_EVP_PKEY_CTX_new_id(int id, ENGINE *e) {
	return EVP_PKEY_CTX_new_id(id, e);
}

int X_EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, void *id, int id_len)
{
	return EVP_PKEY_CTX_set1_id(ctx, id, id_len);
}

int X_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx) {
	return EVP_PKEY_keygen_init(ctx);
}

int X_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
	return EVP_PKEY_keygen(ctx, ppkey);
}

int X_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx) {
	return EVP_PKEY_paramgen_init(ctx);
}

int X_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey) {
	return EVP_PKEY_paramgen(ctx, ppkey);
}

int X_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx) {
	return EVP_PKEY_encrypt_init(ctx);
}

int X_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen)
{
	return EVP_PKEY_encrypt(ctx, out, outlen, in, inlen);
}

int X_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx) {
	return EVP_PKEY_decrypt_init(ctx);
}

int X_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                        const unsigned char *in, size_t inlen)
{
	return EVP_PKEY_decrypt(ctx, out, outlen, in, inlen);
}

BIGNUM *X_BN_new(void) {
	return BN_new();
}

void X_BN_free(BIGNUM *a) {
	BN_free(a);
}

int X_BN_set_word(BIGNUM *a, unsigned long w) {
	return BN_set_word(a, w);
}

char *X_CString(const char *str) {
	return (char *)str;
}

void X_free(void *ptr) {
	OPENSSL_free(ptr);
}

EVP_PKEY_CTX *X_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e) {
	return EVP_PKEY_CTX_new(pkey, e);
}

void X_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx) {
	EVP_PKEY_CTX_free(ctx);
}

int X_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx) {
	return EVP_PKEY_derive_init(ctx);
}

int X_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer) {
	return EVP_PKEY_derive_set_peer(ctx, peer);
}

int X_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen) {
	return EVP_PKEY_derive(ctx, key, pkeylen);
}

const ASN1_TIME *X_X509_get0_notBefore(const X509 *x) {
	return X509_get0_notBefore(x);
}

const ASN1_TIME *X_X509_get0_notAfter(const X509 *x) {
	return X509_get0_notAfter(x);
}

HMAC_CTX *X_HMAC_CTX_new(void) {
	return HMAC_CTX_new();
}

void X_HMAC_CTX_free(HMAC_CTX *ctx) {
	HMAC_CTX_free(ctx);
}

int X_PEM_write_bio_PrivateKey_traditional(BIO *bio, EVP_PKEY *key, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u) {
	return PEM_write_bio_PrivateKey_traditional(bio, key, enc, kstr, klen, cb, u);
}

int X_tscrypto_init() {
	int rc = 0;

	// OpenSSL 3.x/Tongsuo 8.5: 大多数初始化函数已变成宏或自动调用
	// OPENSSL_init_ssl() 会在第一次使用 SSL API 时自动调用

	// OpenSSL 3.x: 线程安全回调已变成空宏，不再需要设置
	// 在 OpenSSL 3.x 中，线程安全由库内部处理

	rc = x_bio_init_methods();
	if (rc != 0) {
		return rc;
	}

	return 0;
}

void * X_OPENSSL_malloc(size_t size) {
	return OPENSSL_malloc(size);
}

void X_OPENSSL_free(void *ref) {
	OPENSSL_free(ref);
}

int X_BIO_get_flags(BIO *b) {
	return BIO_get_flags(b);
}

void X_BIO_set_flags(BIO *b, int flags) {
	return BIO_set_flags(b, flags);
}

void X_BIO_clear_flags(BIO *b, int flags) {
	BIO_clear_flags(b, flags);
}

int X_BIO_read(BIO *b, void *buf, int len) {
	return BIO_read(b, buf, len);
}

int X_BIO_write(BIO *b, const void *buf, int len) {
	return BIO_write(b, buf, len);
}

BIO *X_BIO_new_write_bio() {
	return BIO_new(BIO_s_writeBio());
}

BIO *X_BIO_new_read_bio() {
	return BIO_new(BIO_s_readBio());
}

int X_BN_num_bytes(const BIGNUM *a)
{
	return BN_num_bytes(a);
}

const EVP_MD *X_EVP_get_digestbyname(const char *name) {
	return EVP_get_digestbyname(name);
}

const EVP_MD *X_EVP_md_null() {
	return EVP_md_null();
}

const EVP_MD *X_EVP_md5() {
	return EVP_md5();
}

#ifndef TONGSUO_VERSION_NUMBER
const EVP_MD *X_EVP_md4() {
	return EVP_md4();
}

const EVP_MD *X_EVP_ripemd160() {
	return EVP_ripemd160();
}
#endif

const EVP_MD *X_EVP_sha224() {
	return EVP_sha224();
}

const EVP_MD *X_EVP_sha1() {
	return EVP_sha1();
}

const EVP_MD *X_EVP_sha256() {
	return EVP_sha256();
}

const EVP_MD *X_EVP_sha384() {
	return EVP_sha384();
}

const EVP_MD *X_EVP_sha512() {
	return EVP_sha512();
}

int X_EVP_MD_size(const EVP_MD *md) {
	return EVP_MD_size(md);
}

int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl) {
	return EVP_DigestInit_ex(ctx, type, impl);
}

int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt) {
	return EVP_DigestUpdate(ctx, d, cnt);
}

int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s) {
	return EVP_DigestFinal_ex(ctx, md, s);
}

EVP_PKEY *X_EVP_PKEY_new(void) {
	return EVP_PKEY_new();
}

void X_EVP_PKEY_free(EVP_PKEY *pkey) {
	EVP_PKEY_free(pkey);
}

int X_EVP_PKEY_size(EVP_PKEY *pkey) {
	return EVP_PKEY_size(pkey);
}

struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey) {
	return EVP_PKEY_get1_RSA(pkey);
}

int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key) {
	return EVP_PKEY_set1_RSA(pkey, key);
}

int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key) {
	return EVP_PKEY_assign(pkey, type, key);
}

int X_EVP_CIPHER_block_size(EVP_CIPHER *c) {
    return EVP_CIPHER_block_size(c);
}

int X_EVP_CIPHER_key_length(EVP_CIPHER *c) {
    return EVP_CIPHER_key_length(c);
}

int X_EVP_CIPHER_iv_length(EVP_CIPHER *c) {
    return EVP_CIPHER_iv_length(c);
}

int X_EVP_CIPHER_nid(EVP_CIPHER *c) {
    return EVP_CIPHER_nid(c);
}

int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_block_size(ctx);
}

int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_key_length(ctx);
}

int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_iv_length(ctx);
}

void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding) {
    //openssl always returns 1 for set_padding
    //hence return value is not checked
    EVP_CIPHER_CTX_set_padding(ctx, padding);
}

const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx) {
    return EVP_CIPHER_CTX_cipher(ctx);
}

int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid) {
	return EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid);
}

int X_EVP_PKEY_is_sm2(EVP_PKEY *pkey)
{
	return EVP_PKEY_is_sm2(pkey);
}

int X_EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type)
{
	return EVP_PKEY_set_alias_type(pkey, type);
}

const int X_EVP_PKEY_SM2 = EVP_PKEY_SM2;

size_t X_HMAC_size(const HMAC_CTX *e) {
	return HMAC_size(e);
}

int X_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl) {
	return HMAC_Init_ex(ctx, key, len, md, impl);
}

int X_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len) {
	return HMAC_Update(ctx, data, len);
}

int X_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len) {
	return HMAC_Final(ctx, md, len);
}

long X_X509_get_version(const X509 *x) {
	return X509_get_version(x);
}

int X_X509_set_version(X509 *x, long version) {
	return X509_set_version(x, version);
}

ECDSA_SIG *X_d2i_ECDSA_SIG(ECDSA_SIG **psig, const unsigned char **ppin, long len)
{
	return d2i_ECDSA_SIG(psig, ppin, len);
}

// SM4 兼容函数（Tongsuo 8.5.0+）
// 使用 EVP API 实现低级 SM4 接口
//
// 警告：这些函数存在以下问题，仅供兼容性使用：
// 1. 性能问题：每次调用都创建/销毁 EVP_CIPHER_CTX，效率低下
// 2. 安全问题：ECB 模式不安全，无法隐藏明文模式（相同明文块产生相同密文块）
// 3. 不提供认证：ECB 模式不具备完整性保护，易受篡改攻击
//
// 生产环境强烈建议使用：
// - GCM 模式（推荐）：提供机密性和认证加密（AEAD）
// - CBC 模式：配合 HMAC/MAC 使用以提供完整性保护
// - 直接使用 EVP_EncryptInit/EVP_DecryptInit 高级 API
//
// 参考：GB/T 32907-2016, NIST SP 800-38A
//
// SM4_KEY 结构体说明：
// - rk[0..rk[3]（前16字节）：存储原始 SM4 密钥
// - rk[4..rk[31]（后112字节）：始终为零（OPENSSL_cleanse 清零）
// SM4_encrypt/SM4_decrypt 从 rk[0..rk[3] 提取16字节作为 EVP 密钥

void SM4_set_key(const unsigned char *key, SM4_KEY *ks) {
    if (!ks || !key) {
        return;
    }

    // 安全清零整个结构体（128字节）
    // 防止残留密钥材料泄露到 rk[4..rk[31] 区域
    OPENSSL_cleanse(ks, sizeof(SM4_KEY));

    // 将原始 16 字节密钥存储在 rk[0..rk[3]
    // rk 是 uint32_t[32]，前4个元素共 16 字节，恰好等于 SM4 密钥长度
    // 符合 GB/T 32907-2016 SM4 分组密码算法（密钥长度 128 位）
    memcpy(ks->rk, key, 16);

    // rk[4..rk[31] 保持为零（已由 OPENSSL_cleanse 清零）
    // SM4_encrypt/SM4_decrypt 仅读取前16字节作为 EVP 密钥
}

int SM4_encrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *ks) {
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    if (!in || !out || !ks) {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_sm4_ecb(), NULL,
                           (const unsigned char*)ks->rk, NULL) != 1) {
        goto err;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out, &outlen, in, 16) != 1) {
        goto err;
    }

    int finalLen = 0;
    if (EVP_EncryptFinal_ex(ctx, out + outlen, &finalLen) != 1) {
        goto err;
    }

    ret = 1;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

int SM4_decrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *ks) {
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = 0;

    if (!in || !out || !ks) {
        return 0;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        return 0;
    }

    if (EVP_DecryptInit_ex(ctx, EVP_sm4_ecb(), NULL,
                           (const unsigned char*)ks->rk, NULL) != 1) {
        goto err;
    }

    EVP_CIPHER_CTX_set_padding(ctx, 0);

    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, out, &outlen, in, 16) != 1) {
        goto err;
    }

    int finalLen = 0;
    if (EVP_DecryptFinal_ex(ctx, out + outlen, &finalLen) != 1) {
        goto err;
    }

    ret = 1;

err:
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// NTLS (国密 TLS) 双证书函数实现在 shim.c 中定义
// 避免 duplicate symbol 错误

// ============================================================================
// 密钥验证和KDF函数 - 符合 NIST SP 800-56A Rev.3 和 RFC 5869
// ============================================================================

// X_EVP_PKEY_public_check 验证公钥的有效性
//
// 安全特性：
// - 验证DH公钥在正确的子群范围内 (1 < y < p-1)
// - 验证EC公钥点在曲线上
// - 检查小subgroup攻击
//
// 符合标准：NIST SP 800-56A Rev.3 Section 5.6.2
int X_EVP_PKEY_public_check(const EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, NULL);
	if (!ctx) {
		return 0;
	}

	int ret = EVP_PKEY_public_check(ctx);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

// X_EVP_PKEY_pairwise_check 验证密钥对的一致性
//
// 安全特性：
// - 验证公钥和私钥是否匹配
// - 检查密钥参数一致性
//
// 符合标准：NIST SP 800-56A Rev.3 Section 5.6.2.1
int X_EVP_PKEY_pairwise_check(const EVP_PKEY *pkey)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)pkey, NULL);
	if (!ctx) {
		return 0;
	}

	int ret = EVP_PKEY_pairwise_check(ctx);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

// X_EVP_KDF_derive 使用 HKDF (RFC 5869) 从共享秘密派生密钥
//
// 使用 OpenSSL 3.x / Tongsuo 8.5 的 EVP_KDF API 实现，
// 替代手写 HKDF 以确保正确性和安全性。
//
// 参数：
//   md - 摘要算法 (推荐 SHA-256 或更强)
//   key - 输入密钥材料 (共享秘密)
//   key_len - 输入密钥材料长度
//   salt - 盐值 (可选，NULL 且 salt_len==0 表示不使用)
//   salt_len - 盐值长度
//   info - 上下文信息 (可选，NULL 且 info_len==0 表示不使用)
//   info_len - 上下文信息长度
//   out - 输出缓冲区
//   out_len - 输出长度
//
// 符合标准：
// - RFC 5869 (HKDF)
// - NIST SP 800-56C (Recommendation for Key Derivation)
//
// 返回值：1 表示成功，0 表示失败
int X_EVP_KDF_derive(const EVP_MD *md,
                    const unsigned char *key, size_t key_len,
                    const unsigned char *salt, size_t salt_len,
                    const unsigned char *info, size_t info_len,
                    unsigned char *out, size_t out_len)
{
	EVP_KDF *kdf = NULL;
	EVP_KDF_CTX *kctx = NULL;
	OSSL_PARAM params[6];
	int ret = 0;

	if (!md || !key || !out || key_len == 0 || out_len == 0) {
		return 0;
	}

	// 验证有长度参数对应的指针非 NULL
	if ((salt_len > 0 && !salt) || (info_len > 0 && !info)) {
		return 0;
	}

	kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
	if (!kdf) {
		goto err;
	}

	kctx = EVP_KDF_CTX_new(kdf);
	if (!kctx) {
		goto err;
	}

	const char *digest_name = EVP_MD_name(md);
	size_t idx = 0;

	params[idx++] = OSSL_PARAM_construct_utf8_string("digest",
		(char *)digest_name, 0);
	params[idx++] = OSSL_PARAM_construct_octet_string("key",
		(void *)key, key_len);

	if (salt != NULL && salt_len > 0) {
		params[idx++] = OSSL_PARAM_construct_octet_string("salt",
			(void *)salt, salt_len);
	}

	if (info != NULL && info_len > 0) {
		params[idx++] = OSSL_PARAM_construct_octet_string("info",
			(void *)info, info_len);
	}

	params[idx] = OSSL_PARAM_construct_end();

	ret = EVP_KDF_derive(kctx, out, out_len, params);

err:
	if (kctx) EVP_KDF_CTX_free(kctx);
	if (kdf) EVP_KDF_free(kdf);

	return ret;
}

// X_CRYPTO_memcmp 常量时间内存比较
//
// 安全特性：
// - 防止时序攻击
// - 执行时间不依赖于数据内容
// - 适用于比较密钥、MAC、签名等敏感数据
//
// 符合标准：NIST SP 800-38B
//
// 返回值：0 表示相等，非零表示不相等
int X_CRYPTO_memcmp(const void *a, const void *b, size_t n)
{
#if OPENSSL_VERSION_NUMBER >= 0x10000000L
	return CRYPTO_memcmp(a, b, n);
#else
	const unsigned char *ca = a;
	const unsigned char *cb = b;
	unsigned char ret = 0;
	size_t i;
	for (i = 0; i < n; i++) {
		ret |= ca[i] ^ cb[i];
	}
	return ret;
#endif
}

// X_SSL_CTX_ticket_key_cb 导出函数指针给 Go 使用
// 初始化为 NULL，由根包 init() 通过 X_set_ticket_key_thunk() 设置
static SSL_CTX_tlsext_ticket_key_cb_fn X_SSL_CTX_ticket_key_cb_ptr = NULL;

// X_set_ticket_key_thunk 设置 ticket key 回调 thunk（由根包 sni.c 的 thunk 实现）
void X_set_ticket_key_thunk(SSL_CTX_tlsext_ticket_key_cb_fn thunk)
{
	X_SSL_CTX_ticket_key_cb_ptr = thunk;
}

// 设置实际的回调函数（由 Go 调用）
void X_SSL_CTX_set_tlsext_ticket_key_cb(SSL_CTX *ctx, SSL_CTX_tlsext_ticket_key_cb_fn cb)
{
#ifdef SSL_CTX_set_tlsext_ticket_key_cb
	SSL_CTX_set_tlsext_ticket_key_cb(ctx, cb);
#endif
	X_SSL_CTX_ticket_key_cb_ptr = cb;
}

// 获取回调函数指针
SSL_CTX_tlsext_ticket_key_cb_fn* X_SSL_CTX_ticket_key_cb(void)
{
	return &X_SSL_CTX_ticket_key_cb_ptr;
}

// SSL methods
int X_SSL_new_index(void)
{
	return SSL_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

long X_SSL_get_options(const SSL *ssl)
{
	return SSL_get_options(ssl);
}

long X_SSL_set_options(SSL *ssl, long options)
{
	return SSL_set_options(ssl, options);
}

long X_SSL_clear_options(SSL *ssl, long options)
{
#ifdef SSL_clear_options
	return SSL_clear_options(ssl, options);
#else
	// 对于不支持 SSL_clear_options 的旧版本
	long current = SSL_get_options(ssl);
	SSL_set_options(ssl, current & ~options);
	return current;
#endif
}

// SSL verify callback function pointer
// 初始化为 NULL，由根包 init() 通过 X_set_ssl_verify_thunk() 设置
// crypto 独立测试时保持 NULL（crypto 测试不需要 SSL 验证回调）
static SSL_verify_cb_fn g_ssl_verify_cb = NULL;

// X_set_ssl_verify_thunk 设置 SSL 验证回调 thunk（由根包 sni.c 的 thunk 实现）
void X_set_ssl_verify_thunk(SSL_verify_cb_fn thunk)
{
	g_ssl_verify_cb = thunk;
}

// X_SSL_verify_cb 获取 SSL 验证回调函数指针
SSL_verify_cb_fn* X_SSL_verify_cb(void)
{
	return &g_ssl_verify_cb;
}

// SSL_CTX methods
int X_SSL_CTX_new_index(void)
{
	return SSL_CTX_get_ex_new_index(0, NULL, NULL, NULL, NULL);
}

const SSL_METHOD* X_NTLS_method(void)
{
#ifdef TONGSUO_VERSION_TEXT
	return NTLS_method();
#else
	return TLS_method();
#endif
}

long X_SSL_CTX_get_options(const SSL_CTX *ctx)
{
	return SSL_CTX_get_options(ctx);
}

long X_SSL_CTX_set_options(SSL_CTX *ctx, long options)
{
	return SSL_CTX_set_options(ctx, options);
}

long X_SSL_CTX_clear_options(SSL_CTX *ctx, long options)
{
#ifdef SSL_CTX_clear_options
	return SSL_CTX_clear_options(ctx, options);
#else
	long current = SSL_CTX_get_options(ctx);
	SSL_CTX_set_options(ctx, current & ~options);
	return current;
#endif
}

long X_SSL_CTX_get_mode(const SSL_CTX *ctx)
{
	return SSL_CTX_get_mode((SSL_CTX *)ctx);
}

long X_SSL_CTX_set_mode(SSL_CTX *ctx, long mode)
{
	return SSL_CTX_set_mode(ctx, mode);
}

long X_SSL_CTX_get_timeout(const SSL_CTX *ctx)
{
	return SSL_CTX_get_timeout(ctx);
}

long X_SSL_CTX_set_timeout(SSL_CTX *ctx, long t)
{
	return SSL_CTX_set_timeout(ctx, t);
}

long X_SSL_CTX_sess_get_cache_size(const SSL_CTX *ctx)
{
	return SSL_CTX_sess_get_cache_size((SSL_CTX *)ctx);
}

long X_SSL_CTX_sess_set_cache_size(SSL_CTX *ctx, long t)
{
	return SSL_CTX_sess_set_cache_size(ctx, t);
}

int X_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version)
{
#ifdef SSL_CTX_set_min_proto_version
	return SSL_CTX_set_min_proto_version(ctx, version);
#else
	return 1; // Success
#endif
}

int X_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version)
{
#ifdef SSL_CTX_set_max_proto_version
	return SSL_CTX_set_max_proto_version(ctx, version);
#else
	return 1; // Success
#endif
}

int X_SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode)
{
	return SSL_CTX_set_session_cache_mode(ctx, mode);
}

int X_SSL_CTX_enable_ntls(SSL_CTX *ctx)
{
#ifdef TONGSUO_VERSION_TEXT
	// Tongsuo exports SSL_CTX_enable_ntls as a function (not a macro),
	// so #ifdef SSL_CTX_enable_ntls fails. Use Tongsuo version check instead.
	SSL_CTX_enable_ntls(ctx);
#endif
	return 1;
}

int X_SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh)
{
	return SSL_CTX_set_tmp_dh(ctx, dh);
}

int X_SSL_CTX_set_tmp_ecdh(SSL_CTX *ctx, EC_KEY *ecdh)
{
	return SSL_CTX_set_tmp_ecdh(ctx, ecdh);
}

int X_SSL_CTX_set_tlsext_servername_callback(SSL_CTX *ctx, void *cb)
{
#ifdef SSL_CTX_set_tlsext_servername_callback
	// cb 实际上是函数指针 sni_cb
	return SSL_CTX_set_tlsext_servername_callback(ctx, (int (*)(SSL *, int *, void *))cb);
#else
	return 1; // Success
#endif
}

int X_SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509)
{
	return SSL_CTX_add_extra_chain_cert(ctx, x509);
}

int X_X509_add_ref(X509 *x509)
{
	return X509_up_ref(x509);
}

// SSL_CTX verify callback
// 初始化为 NULL，由根包 init() 通过 X_set_ssl_ctx_verify_thunk() 设置
static SSL_CTX_verify_cb_fn g_ssl_ctx_verify_cb = NULL;

// X_set_ssl_ctx_verify_thunk 设置 SSL_CTX 验证回调 thunk（由根包 sni.c 的 thunk 实现）
void X_set_ssl_ctx_verify_thunk(SSL_CTX_verify_cb_fn thunk)
{
	g_ssl_ctx_verify_cb = thunk;
}

SSL_CTX_verify_cb_fn* X_SSL_CTX_verify_cb(void)
{
	return &g_ssl_ctx_verify_cb;
}

// ALPN/SNI callback pointers (exported for Go)
// 这些函数在 sni.c 中实现，这里不需要声明

// Additional SSL functions
const char* X_SSL_get_version(const SSL *ssl)
{
	return SSL_get_version(ssl);
}

const char* X_SSL_get_cipher_name(const SSL *ssl)
{
	return SSL_get_cipher_name(ssl);
}

int X_SSL_session_reused(const SSL *ssl)
{
	return SSL_session_reused(ssl);
}

int X_SSL_set_tlsext_host_name(SSL *ssl, const char *name)
{
#ifdef SSL_set_tlsext_host_name
	return SSL_set_tlsext_host_name(ssl, name);
#else
	return 1; // Success if not supported
#endif
}

// STACK_OF(X509) accessor functions
int X_sk_X509_num(const STACK_OF(X509) *sk)
{
	return sk_X509_num(sk);
}

X509* X_sk_X509_value(const STACK_OF(X509) *sk, int index)
{
	return sk_X509_value(sk, index);
}

// ============================================================================
// OCSP functions
// ============================================================================

OCSP_CERTID *X_OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject, const X509 *issuer)
{
	return OCSP_cert_to_id(dgst, subject, issuer);
}

OCSP_BASICRESP *X_OCSP_BASICRESP_new(void)
{
	return OCSP_BASICRESP_new();
}

void X_OCSP_BASICRESP_free(OCSP_BASICRESP *bs)
{
	OCSP_BASICRESP_free(bs);
}

OCSP_SINGLERESP *X_OCSP_basic_add1_status(OCSP_BASICRESP *bs, OCSP_CERTID *cid, int status, int reason,
                                         ASN1_TIME *revtime, ASN1_TIME *thisupd, ASN1_TIME *nextupd)
{
	return OCSP_basic_add1_status(bs, cid, status, reason, revtime, thisupd, nextupd);
}

int X_OCSP_basic_sign(OCSP_BASICRESP *bs, X509 *signer, EVP_PKEY *key,
                       const EVP_MD *dgst, STACK_OF(X509) *certs, unsigned long flags)
{
	return OCSP_basic_sign(bs, signer, key, dgst, certs, flags);
}

OCSP_RESPONSE *X_OCSP_response_create(int status, OCSP_BASICRESP *bs)
{
	return OCSP_response_create(status, bs);
}

void X_OCSP_response_free(OCSP_RESPONSE *r)
{
	OCSP_RESPONSE_free(r);
}

int X_i2d_OCSP_RESPONSE(OCSP_RESPONSE *r, unsigned char **out)
{
	return i2d_OCSP_RESPONSE(r, out);
}

OCSP_RESPONSE *X_d2i_OCSP_RESPONSE(OCSP_RESPONSE **r, const unsigned char **ppin, long len)
{
	return d2i_OCSP_RESPONSE(r, ppin, len);
}

int X_OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
                            int *reason, ASN1_TIME **revtime,
                            ASN1_TIME **thisupd, ASN1_TIME **nextupd)
{
	return OCSP_resp_find_status(bs, id, status, reason, revtime, thisupd, nextupd);
}

int X_OCSP_response_status(OCSP_RESPONSE *r)
{
	return OCSP_response_status(r);
}

OCSP_BASICRESP *X_OCSP_response_get1_basic(OCSP_RESPONSE *r)
{
	return OCSP_response_get1_basic(r);
}

/* PKCS8 helpers */
PKCS8_PRIV_KEY_INFO *X_EVP_PKEY2PKCS8(EVP_PKEY *pkey)
{
	return EVP_PKEY2PKCS8(pkey);
}

void X_PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *p8)
{
	PKCS8_PRIV_KEY_INFO_free(p8);
}

int X_i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bio, PKCS8_PRIV_KEY_INFO *p8)
{
	return i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8);
}

// ============================================================================
// EC_KEY / ECDH helpers for SM2 key agreement
// ============================================================================

EC_KEY *X_EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey)
{
	return EVP_PKEY_get1_EC_KEY(pkey);
}

void X_EC_KEY_free(EC_KEY *key)
{
	EC_KEY_free(key);
}

const EC_GROUP *X_EC_KEY_get0_group(const EC_KEY *key)
{
	return EC_KEY_get0_group(key);
}

const EC_POINT *X_EC_KEY_get0_public_key(const EC_KEY *key)
{
	return EC_KEY_get0_public_key(key);
}

int X_ECDH_compute_key(void *out, size_t outlen,
                        const EC_POINT *pub_key, const EC_KEY *ecdh,
                        void *(*KDF)(const void *in, size_t inlen,
                                     void *out, size_t *outlen))
{
	return ECDH_compute_key(out, outlen, pub_key, ecdh, KDF);
}

/* ============================================================
 * PKI toolchain: CSR, CRL, certificate chain verification
 * ============================================================ */

/* CSR signing with EVP_MD_CTX (needed for SM2) */
int X_X509_REQ_sign_ctx(X509_REQ *req, EVP_MD_CTX *ctx)
{
	return X509_REQ_sign_ctx(req, ctx);
}

/* CRL signing with EVP_MD_CTX (needed for SM2) */
int X_X509_CRL_sign_ctx(X509_CRL *crl, EVP_MD_CTX *ctx)
{
	return X509_CRL_sign_ctx(crl, ctx);
}

/* CSR extension helper: add a single extension by NID */
int X_X509_REQ_add1_ext(X509_REQ *req, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509V3_set_ctx(&ctx, NULL, NULL, req, NULL, 0);
	X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value);
	if (!ext)
		return 0;

	STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();
	if (!exts) {
		X509_EXTENSION_free(ext);
		return 0;
	}
	sk_X509_EXTENSION_push(exts, ext);
	int ret = X509_REQ_add_extensions(req, exts);
	sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
	return ret;
}

/* CRL helpers */
int X_X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev)
{
	return X509_CRL_add0_revoked(crl, rev);
}

/* CRL revoked entry stack accessors */
int X_sk_X509_REVOKED_num(const STACK_OF(X509_REVOKED) *sk)
{
	return sk_X509_REVOKED_num(sk);
}

X509_REVOKED *X_sk_X509_REVOKED_value(const STACK_OF(X509_REVOKED) *sk, int i)
{
	return sk_X509_REVOKED_value(sk, i);
}

/* X509 stack helpers for chain verification */
STACK_OF(X509) *X_sk_X509_new_null(void)
{
	return sk_X509_new_null();
}

int X_sk_X509_push(STACK_OF(X509) *sk, X509 *x)
{
	return sk_X509_push(sk, x);
}

void X_sk_X509_free(STACK_OF(X509) *sk)
{
	sk_X509_free(sk);
}

/* Certificate chain verification helpers */
STACK_OF(X509) *X_X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx)
{
	return X509_STORE_CTX_get0_chain(ctx);
}

void X_X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk)
{
	X509_STORE_CTX_set0_untrusted(ctx, sk);
}

/* BN helpers (BN_num_bytes is a macro, not visible to CGo) */
int X_BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
	return BN_bn2bin(a, to);
}

/* ============================================================
 * ZUC EIA3 authentication (GM/T 0001-2012 128-EIA3)
 * EIA3_CTX is opaque; internal header not installed,
 * so we forward-declare and use EIA3_ctx_size() for allocation.
 * ============================================================ */

size_t X_EIA3_ctx_size(void)
{
	extern size_t EIA3_ctx_size(void);
	return EIA3_ctx_size();
}

void* X_EIA3_CTX_new(void)
{
	size_t sz = X_EIA3_ctx_size();
	void *ctx = OPENSSL_malloc(sz);
	if (ctx)
		memset(ctx, 0, sz);
	return ctx;
}

void X_EIA3_CTX_free(void *ctx)
{
	if (ctx) {
		OPENSSL_cleanse(ctx, X_EIA3_ctx_size());
		OPENSSL_free(ctx);
	}
}

int X_EIA3_Init(void *ctx, const unsigned char *key, const unsigned char *iv)
{
	/* EIA3_CTX is forward-declared; linker resolves the actual symbol.
	 * The function prototype uses EIA3_CTX* but C allows void* to
	 * any-pointer implicit conversion for function arguments. */
	extern int EIA3_Init(void *, const unsigned char *, const unsigned char *);
	return EIA3_Init(ctx, key, iv);
}

int X_EIA3_Update(void *ctx, const unsigned char *inp, size_t len)
{
	extern int EIA3_Update(void *, const unsigned char *, size_t);
	return EIA3_Update(ctx, inp, len);
}

void X_EIA3_Final(void *ctx, unsigned char *out)
{
	extern void EIA3_Final(void *, unsigned char *);
	EIA3_Final(ctx, out);
}

/* X509 name check wrappers (accept const char* to match C.CString) */
int X_X509_check_host(X509 *x, const char *chk, size_t chklen,
                      unsigned int flags)
{
    return X509_check_host(x, chk, chklen, flags, NULL);
}

int X_X509_check_email(X509 *x, const char *chk, size_t chklen,
                       unsigned int flags)
{
    return X509_check_email(x, chk, chklen, flags);
}

int X_X509_check_ip(X509 *x, const unsigned char *chk, size_t chklen,
                    unsigned int flags)
{
    return X509_check_ip(x, chk, chklen, flags);
}

/* ============================================================
 * OCSP Stapling helpers
 * These are macros in tls1.h, need C wrappers for CGo.
 * ============================================================ */

int X_SSL_set_tlsext_status_type(SSL *ssl, int type)
{
	return SSL_set_tlsext_status_type(ssl, type);
}

int X_SSL_set_tlsext_status_ocsp_resp(SSL *ssl, const unsigned char *resp, size_t len)
{
	return SSL_set_tlsext_status_ocsp_resp(ssl, (unsigned char *)resp, len);
}

int X_SSL_get_tlsext_status_ocsp_resp(SSL *ssl, const unsigned char **resp)
{
	return SSL_get_tlsext_status_ocsp_resp(ssl, resp);
}
