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

#ifndef TONGSUO_GO_SDK_CRYPTO_SHIM_H
#define TONGSUO_GO_SDK_CRYPTO_SHIM_H

#include <stdlib.h>
#include <string.h>

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/ocsp.h>

// SM4 兼容层（Tongsuo 8.5.0+）
// 使用内部头文件 crypto/sm4.h 中的定义
#define SM4_KEY_SIZE 16
#define SM4_BLOCK_SIZE 16

// SM4_KEY 结构体定义与内部 crypto/sm4.h 匹配
typedef struct SM4_KEY_st {
    uint32_t rk[32];  // SM4_KEY_SCHEDULE = 32
} SM4_KEY;

// SM4 函数声明（使用 EVP API 实现）
// 返回值：1 表示成功，0 表示失败
extern void SM4_set_key(const unsigned char *key, SM4_KEY *ks);
extern int SM4_encrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *ks);
extern int SM4_decrypt(const unsigned char *in, unsigned char *out, const SM4_KEY *ks);

/* shim  methods */
extern int X_tscrypto_init();

/* Library methods */
extern void X_OPENSSL_free(void *ref);
extern void *X_OPENSSL_malloc(size_t size);

/* BIO methods */
extern int X_BIO_get_flags(BIO *b);
extern void X_BIO_set_flags(BIO *bio, int flags);
extern void X_BIO_clear_flags(BIO *bio, int flags);
extern void X_BIO_set_data(BIO *bio, void* data);
extern void *X_BIO_get_data(BIO *bio);
extern int X_BIO_read(BIO *b, void *buf, int len);
extern int X_BIO_write(BIO *b, const void *buf, int len);
extern BIO *X_BIO_new_write_bio();
extern BIO *X_BIO_new_read_bio();
extern long X_BIO_get_mem_data(BIO *b, char **pp);

extern int X_BN_num_bytes(const BIGNUM *a);

/* EVP methods */
extern const int X_ED25519_SUPPORT;
extern int X_EVP_PKEY_ED25519;
extern const EVP_MD *X_EVP_get_digestbyname(const char *name);
extern EVP_MD_CTX *X_EVP_MD_CTX_new();
extern int X_EVP_MD_CTX_copy_ex(EVP_MD_CTX *out, const EVP_MD_CTX *in);
extern void X_EVP_MD_CTX_free(EVP_MD_CTX *ctx);
extern const EVP_MD *X_EVP_md_null();
extern const EVP_MD *X_EVP_md5();
extern const EVP_MD *X_EVP_md4();
extern const EVP_MD *X_EVP_sha();
extern const EVP_MD *X_EVP_sha1();
extern const EVP_MD *X_EVP_dss();
extern const EVP_MD *X_EVP_dss1();
extern const EVP_MD *X_EVP_ripemd160();
extern const EVP_MD *X_EVP_sha224();
extern const EVP_MD *X_EVP_sha256();
extern const EVP_MD *X_EVP_sha384();
extern const EVP_MD *X_EVP_sha512();
extern const EVP_MD *X_EVP_sm3();
extern int X_EVP_MD_size(const EVP_MD *md);
extern int X_EVP_DigestInit_ex(EVP_MD_CTX *ctx, const EVP_MD *type, ENGINE *impl);
extern int X_EVP_DigestUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestFinal_ex(EVP_MD_CTX *ctx, unsigned char *md, unsigned int *s);
extern int X_EVP_DigestSignInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int X_EVP_DigestSignUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestSignFinal(EVP_MD_CTX *ctx, unsigned char *sig, size_t *siglen);
extern int X_EVP_DigestSign(EVP_MD_CTX *ctx, unsigned char *sigret, size_t *siglen, const unsigned char *tbs, size_t tbslen);
extern int X_EVP_Digest(const void *data, size_t count, unsigned char *md, unsigned int *size, const EVP_MD *type, ENGINE *impl);
extern EVP_PKEY *X_EVP_PKEY_new(void);
extern void X_EVP_PKEY_free(EVP_PKEY *pkey);
extern int X_EVP_PKEY_size(EVP_PKEY *pkey);
extern struct rsa_st *X_EVP_PKEY_get1_RSA(EVP_PKEY *pkey);
extern int X_EVP_PKEY_set1_RSA(EVP_PKEY *pkey, struct rsa_st *key);
extern int X_EVP_PKEY_assign_charp(EVP_PKEY *pkey, int type, char *key);
extern int X_EVP_DigestVerifyInit(EVP_MD_CTX *ctx, EVP_PKEY_CTX **pctx, const EVP_MD *type, ENGINE *e, EVP_PKEY *pkey);
extern int X_EVP_DigestVerifyUpdate(EVP_MD_CTX *ctx, const void *d, size_t cnt);
extern int X_EVP_DigestVerifyFinal(EVP_MD_CTX *ctx, const unsigned char *sig, size_t siglen);
extern int X_EVP_DigestVerify(EVP_MD_CTX *ctx, const unsigned char *sigret, size_t siglen, const unsigned char *tbs, size_t tbslen);
extern int X_EVP_CIPHER_block_size(EVP_CIPHER *c);
extern int X_EVP_CIPHER_key_length(EVP_CIPHER *c);
extern int X_EVP_CIPHER_iv_length(EVP_CIPHER *c);
extern int X_EVP_CIPHER_nid(EVP_CIPHER *c);
extern int X_EVP_CIPHER_CTX_block_size(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_key_length(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_iv_length(EVP_CIPHER_CTX *ctx);
extern void X_EVP_CIPHER_CTX_set_padding(EVP_CIPHER_CTX *ctx, int padding);
extern const EVP_CIPHER *X_EVP_CIPHER_CTX_cipher(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_encrypting(const EVP_CIPHER_CTX *ctx);
extern EVP_CIPHER_CTX *X_EVP_CIPHER_CTX_new();
extern void X_EVP_CIPHER_CTX_free(EVP_CIPHER_CTX *ctx);
extern int X_EVP_CIPHER_CTX_reset(EVP_CIPHER_CTX *ctx);
extern const EVP_CIPHER *X_EVP_sm4_ecb();
extern int X_EVP_EncryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
extern int X_EVP_EncryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
extern int X_EVP_EncryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);
extern int X_EVP_DecryptInit_ex(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv);
extern int X_EVP_DecryptUpdate(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl);
extern int X_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);

/* EVP_PKEY_CTX methods */
extern EVP_PKEY_CTX *X_EVP_PKEY_CTX_new(EVP_PKEY *pkey, ENGINE *e);
extern EVP_PKEY_CTX *X_EVP_PKEY_CTX_new_id(int id, ENGINE *e);
extern void X_EVP_PKEY_CTX_free(EVP_PKEY_CTX *ctx);
extern int X_EVP_PKEY_CTX_set1_id(EVP_PKEY_CTX *ctx, void *id, int id_len);
extern int X_EVP_PKEY_keygen_init(EVP_PKEY_CTX *ctx);
extern int X_EVP_PKEY_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
extern int X_EVP_PKEY_paramgen_init(EVP_PKEY_CTX *ctx);
extern int X_EVP_PKEY_paramgen(EVP_PKEY_CTX *ctx, EVP_PKEY **ppkey);
extern int X_EVP_PKEY_derive_init(EVP_PKEY_CTX *ctx);
extern int X_EVP_PKEY_derive_set_peer(EVP_PKEY_CTX *ctx, EVP_PKEY *peer);
extern int X_EVP_PKEY_derive(EVP_PKEY_CTX *ctx, unsigned char *key, size_t *pkeylen);
extern int X_EVP_PKEY_CTX_set_ec_paramgen_curve_nid(EVP_PKEY_CTX *ctx, int nid);
extern int X_EVP_PKEY_is_sm2(EVP_PKEY *pkey);
extern int X_EVP_PKEY_set_alias_type(EVP_PKEY *pkey, int type);
extern const int X_EVP_PKEY_SM2;
extern int X_EVP_PKEY_CTX_set_rsa_keygen_bits(EVP_PKEY_CTX *ctx, int bits);
extern int X_EVP_PKEY_CTX_set_rsa_keygen_pubexp(EVP_PKEY_CTX *ctx, BIGNUM *pubexp);

/* EVP_PKEY encryption/decryption */
extern int X_EVP_PKEY_encrypt_init(EVP_PKEY_CTX *ctx);
extern int X_EVP_PKEY_encrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen);
extern int X_EVP_PKEY_decrypt_init(EVP_PKEY_CTX *ctx);
extern int X_EVP_PKEY_decrypt(EVP_PKEY_CTX *ctx, unsigned char *out, size_t *outlen,
                              const unsigned char *in, size_t inlen);

/* BIGNUM methods */
extern BIGNUM *X_BN_new(void);
extern void X_BN_free(BIGNUM *a);
extern int X_BN_set_word(BIGNUM *a, unsigned long w);
extern int X_BN_num_bytes(const BIGNUM *a);
extern int X_BN_bn2bin(const BIGNUM *a, unsigned char *to);

/* String and memory allocation helpers */
extern char *X_CString(const char *str);
extern void X_free(void *ptr);

/* 密钥验证函数 - 符合 NIST SP 800-56A Rev.3 */
extern int X_EVP_PKEY_public_check(const EVP_PKEY *pkey);
extern int X_EVP_PKEY_pairwise_check(const EVP_PKEY *pkey);

/* KDF 函数 - HKDF from PKCS#3 */
extern int X_EVP_KDF_derive(const EVP_MD *md,
                            const unsigned char *key, size_t key_len,
                            const unsigned char *salt, size_t salt_len,
                            const unsigned char *info, size_t info_len,
                            unsigned char *out, size_t out_len);

/* 常量时间比较 */
extern int X_CRYPTO_memcmp(const void *a, const void *b, size_t n);

/* HMAC methods */
extern size_t X_HMAC_size(const HMAC_CTX *e);
extern HMAC_CTX *X_HMAC_CTX_new(void);
extern void X_HMAC_CTX_free(HMAC_CTX *ctx);
extern int X_HMAC_Init_ex(HMAC_CTX *ctx, const void *key, int len, const EVP_MD *md, ENGINE *impl);
extern int X_HMAC_Update(HMAC_CTX *ctx, const unsigned char *data, size_t len);
extern int X_HMAC_Final(HMAC_CTX *ctx, unsigned char *md, unsigned int *len);

/* X509 methods */
extern const ASN1_TIME *X_X509_get0_notBefore(const X509 *x);
extern const ASN1_TIME *X_X509_get0_notAfter(const X509 *x);
extern long X_X509_get_version(const X509 *x);
extern int X_X509_set_version(X509 *x, long version);

/* PEM methods */
extern int X_PEM_write_bio_PrivateKey_traditional(BIO *bio, EVP_PKEY *key, const EVP_CIPHER *enc, unsigned char *kstr, int klen, pem_password_cb *cb, void *u);

/* ASN.1 methods */
extern ECDSA_SIG *X_d2i_ECDSA_SIG(ECDSA_SIG **psig, const unsigned char **ppin, long len);

/* BIO methods */
extern BIO *BIO_new(const BIO_METHOD *type);
extern int BIO_free(BIO *a);
extern long BIO_ctrl(BIO *bp, int cmd, long larg, void *parg);

/* BIO_CTRL constants - 使用 ifndef 保护避免重定义 */
#ifndef BIO_CTRL_RESET
#define BIO_CTRL_RESET 1
#endif
#ifndef BIO_CTRL_EOF
#define BIO_CTRL_EOF 2
#endif
#ifndef BIO_CTRL_INFO
#define BIO_CTRL_INFO 3
#endif
#ifndef BIO_CTRL_SET
#define BIO_CTRL_SET 4
#endif
#ifndef BIO_CTRL_GET
#define BIO_CTRL_GET 5
#endif
#ifndef BIO_CTRL_PUSH
#define BIO_CTRL_PUSH 6
#endif
#ifndef BIO_CTRL_POP
#define BIO_CTRL_POP 7
#endif
#ifndef BIO_CTRL_DUP
#define BIO_CTRL_DUP 8
#endif
#ifndef BIO_CTRL_FLUSH
#define BIO_CTRL_FLUSH 11
#endif
#ifndef BIO_CTRL_WPENDING
#define BIO_CTRL_WPENDING 13
#endif

/* EVP_CTRL constants for GCM - 使用 ifndef 保护避免重定义 */
#ifndef EVP_CTRL_GCM_SET_IVLEN
#define EVP_CTRL_GCM_SET_IVLEN 0x1009
#endif
#ifndef EVP_CTRL_GCM_GET_TAG
#define EVP_CTRL_GCM_GET_TAG 0x1010
#endif
#ifndef EVP_CTRL_GCM_SET_TAG
#define EVP_CTRL_GCM_SET_TAG 0x1011
#endif

/* C standard types */
typedef unsigned char uchar;

/* OpenSSL cleanse */
void OPENSSL_cleanse(void *ptr, size_t len);

/* SSL/TLS ticket key callback */
typedef int (*SSL_CTX_tlsext_ticket_key_cb_fn)(SSL *ssl,
                                                unsigned char *key_name,
                                                unsigned char *iv,
                                                EVP_CIPHER_CTX *ctx,
                                                HMAC_CTX *hctx,
                                                int enc);

extern void X_SSL_CTX_set_tlsext_ticket_key_cb(SSL_CTX *ctx, SSL_CTX_tlsext_ticket_key_cb_fn cb);
extern SSL_CTX_tlsext_ticket_key_cb_fn* X_SSL_CTX_ticket_key_cb(void);

/* SSL methods */
extern int X_SSL_new_index(void);
extern long X_SSL_get_options(const SSL *ssl);
extern long X_SSL_set_options(SSL *ssl, long options);
extern long X_SSL_clear_options(SSL *ssl, long options);

/* SSL verify callback */
typedef int (*SSL_verify_cb_fn)(int ok, X509_STORE_CTX *ctx);
extern SSL_verify_cb_fn* X_SSL_verify_cb(void);

/* SSL_CTX methods */
extern int X_SSL_CTX_new_index(void);
extern const SSL_METHOD* X_NTLS_method(void);
extern long X_SSL_CTX_get_options(const SSL_CTX *ctx);
extern long X_SSL_CTX_set_options(SSL_CTX *ctx, long options);
extern long X_SSL_CTX_clear_options(SSL_CTX *ctx, long options);
extern long X_SSL_CTX_get_mode(const SSL_CTX *ctx);
extern long X_SSL_CTX_set_mode(SSL_CTX *ctx, long mode);
extern long X_SSL_CTX_get_timeout(const SSL_CTX *ctx);
extern long X_SSL_CTX_set_timeout(SSL_CTX *ctx, long t);
extern long X_SSL_CTX_sess_get_cache_size(const SSL_CTX *ctx);
extern long X_SSL_CTX_sess_set_cache_size(SSL_CTX *ctx, long t);
extern int X_SSL_CTX_set_min_proto_version(SSL_CTX *ctx, int version);
extern int X_SSL_CTX_set_max_proto_version(SSL_CTX *ctx, int version);
extern int X_SSL_CTX_set_session_cache_mode(SSL_CTX *ctx, long mode);
extern int X_SSL_CTX_enable_ntls(SSL_CTX *ctx);
extern int X_SSL_CTX_set_tmp_dh(SSL_CTX *ctx, DH *dh);
extern int X_SSL_CTX_set_tmp_ecdh(SSL_CTX *ctx, EC_KEY *ecdh);
extern int X_SSL_CTX_set_tlsext_servername_callback(SSL_CTX *ctx, void *cb);
extern int X_SSL_CTX_add_extra_chain_cert(SSL_CTX *ctx, X509 *x509);
extern int X_X509_add_ref(X509 *x509);

/* SSL_CTX verify callback */
typedef int (*SSL_CTX_verify_cb_fn)(int ok, X509_STORE_CTX *ctx);
extern SSL_CTX_verify_cb_fn* X_SSL_CTX_verify_cb(void);

/* ALPN/SNI callback types */
typedef int (*alpn_cb_fn)(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
typedef int (*sni_cb_fn)(SSL *ssl, int *ad, void *arg);

// 这些函数在 sni.c 中实现
extern int sni_cb(SSL *ssl, int *ad, void *arg);
extern int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);

/* Additional SSL functions */
extern const char* X_SSL_get_version(const SSL *ssl);
extern const char* X_SSL_get_cipher_name(const SSL *ssl);
extern int X_SSL_session_reused(const SSL *ssl);
extern int X_SSL_set_tlsext_host_name(SSL *ssl, const char *name);

/* STACK_OF(X509) accessor functions */
extern int X_sk_X509_num(const STACK_OF(X509) *sk);
extern X509* X_sk_X509_value(const STACK_OF(X509) *sk, int index);

/* Cross-CGO-unit thunk initialization (implemented in sni.c) */
extern void X_init_crypto_thunks(void);

/* Cross-CGO-unit thunk setters (implemented in crypto/shim.c) */
extern void X_set_ssl_verify_thunk(SSL_verify_cb_fn thunk);
extern void X_set_ssl_ctx_verify_thunk(SSL_CTX_verify_cb_fn thunk);
extern void X_set_ticket_key_thunk(SSL_CTX_tlsext_ticket_key_cb_fn thunk);

/* OCSP methods */
extern OCSP_CERTID *X_OCSP_cert_to_id(const EVP_MD *dgst, const X509 *subject, const X509 *issuer);
extern OCSP_BASICRESP *X_OCSP_BASICRESP_new(void);
extern void X_OCSP_BASICRESP_free(OCSP_BASICRESP *bs);
extern OCSP_SINGLERESP *X_OCSP_basic_add1_status(OCSP_BASICRESP *bs, OCSP_CERTID *cid, int status, int reason,
                                                  ASN1_TIME *revtime, ASN1_TIME *thisupd, ASN1_TIME *nextupd);
extern int X_OCSP_basic_sign(OCSP_BASICRESP *bs, X509 *signer, EVP_PKEY *key,
                             const EVP_MD *dgst, STACK_OF(X509) *certs, unsigned long flags);
extern OCSP_RESPONSE *X_OCSP_response_create(int status, OCSP_BASICRESP *bs);
extern void X_OCSP_response_free(OCSP_RESPONSE *r);
extern int X_i2d_OCSP_RESPONSE(OCSP_RESPONSE *r, unsigned char **out);
extern OCSP_RESPONSE *X_d2i_OCSP_RESPONSE(OCSP_RESPONSE **r, const unsigned char **ppin, long len);
extern int X_OCSP_resp_find_status(OCSP_BASICRESP *bs, OCSP_CERTID *id, int *status,
                                   int *reason, ASN1_TIME **revtime,
                                   ASN1_TIME **thisupd, ASN1_TIME **nextupd);
extern int X_OCSP_response_status(OCSP_RESPONSE *r);
extern OCSP_BASICRESP *X_OCSP_response_get1_basic(OCSP_RESPONSE *r);

/* PKCS8 helpers */
extern PKCS8_PRIV_KEY_INFO *X_EVP_PKEY2PKCS8(EVP_PKEY *pkey);
extern void X_PKCS8_PRIV_KEY_INFO_free(PKCS8_PRIV_KEY_INFO *p8);
extern int X_i2d_PKCS8_PRIV_KEY_INFO_bio(BIO *bio, PKCS8_PRIV_KEY_INFO *p8);

/* EC_KEY / ECDH helpers for SM2 key agreement */
extern EC_KEY *X_EVP_PKEY_get1_EC_KEY(EVP_PKEY *pkey);
extern void X_EC_KEY_free(EC_KEY *key);
extern const EC_GROUP *X_EC_KEY_get0_group(const EC_KEY *key);
extern const EC_POINT *X_EC_KEY_get0_public_key(const EC_KEY *key);
extern int X_ECDH_compute_key(void *out, size_t outlen,
                               const EC_POINT *pub_key, const EC_KEY *ecdh,
                               void *(*KDF)(const void *in, size_t inlen,
                                            void *out, size_t *outlen));

/* PKI toolchain: CSR, CRL, certificate chain verification */
extern int X_X509_REQ_sign_ctx(X509_REQ *req, EVP_MD_CTX *ctx);
extern int X_X509_REQ_add1_ext(X509_REQ *req, int nid, const char *value);
extern int X_X509_CRL_sign_ctx(X509_CRL *crl, EVP_MD_CTX *ctx);
extern int X_X509_CRL_add0_revoked(X509_CRL *crl, X509_REVOKED *rev);
extern int X_sk_X509_REVOKED_num(const STACK_OF(X509_REVOKED) *sk);
extern X509_REVOKED *X_sk_X509_REVOKED_value(const STACK_OF(X509_REVOKED) *sk, int i);
extern STACK_OF(X509) *X_sk_X509_new_null(void);
extern int X_sk_X509_push(STACK_OF(X509) *sk, X509 *x);
extern void X_sk_X509_free(STACK_OF(X509) *sk);
extern STACK_OF(X509) *X_X509_STORE_CTX_get0_chain(const X509_STORE_CTX *ctx);
extern void X_X509_STORE_CTX_set0_untrusted(X509_STORE_CTX *ctx, STACK_OF(X509) *sk);

// SSL curve/group setting (macro wrapper)
extern int X_SSL_CTX_set1_curves(SSL_CTX *ctx, const int *curves, size_t len);

// cgo.Handle ↔ void* helpers (avoids unsafe.Pointer vet false positive)
extern void* X_cgo_handle_to_ptr(intptr_t h);
extern intptr_t X_cgo_ptr_to_handle(void* p);

/* ZUC EIA3 authentication (GM/T 0001-2012 128-EIA3) */
#define EIA3_DIGEST_SIZE 4

extern size_t X_EIA3_ctx_size(void);
extern void* X_EIA3_CTX_new(void);
extern void X_EIA3_CTX_free(void *ctx);
extern int X_EIA3_Init(void *ctx, const unsigned char *key, const unsigned char *iv);
extern int X_EIA3_Update(void *ctx, const unsigned char *inp, size_t len);
extern void X_EIA3_Final(void *ctx, unsigned char *out);

/* OCSP Stapling helpers (macros need C wrappers for CGo) */
extern int X_SSL_set_tlsext_status_type(SSL *ssl, int type);
extern int X_SSL_set_tlsext_status_ocsp_resp(SSL *ssl, const unsigned char *resp, size_t len);
extern int X_SSL_get_tlsext_status_ocsp_resp(SSL *ssl, const unsigned char **resp);

#endif /* TONGSUO_GO_SDK_CRYPTO_SHIM_H */
