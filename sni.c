// Copyright (C) 2017. See AUTHORS.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <openssl/ssl.h>
#include "_cgo_export.h"
#include <stdio.h>

// SNI callback - 从 SSL_CTX ex_data 获取 Go Ctx 指针
int sni_cb(SSL *con, int *ad, void *arg) {
	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(con);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	return sniCbThunk(p, con, ad, arg);
}

// ALPN callback - 从 SSL_CTX ex_data 获取 Go Ctx 指针
int alpn_cb(SSL *ssl_conn, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg) {
	SSL_CTX* ssl_ctx = SSL_get_SSL_CTX(ssl_conn);
	void* p = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	return alpn_cb_thunk(p, ssl_conn, (unsigned char **)out, outlen, (unsigned char *)in, inlen, arg);
}

// SSL verify callback thunk (C-01 fix)
//
// OpenSSL 通过 SSL_set_verify 注册的验证回调。
// 从 X509_STORE_CTX ex_data 提取 SSL*，再从 SSL ex_data 获取 Go *SSL。
//
// 修复前：g_ssl_verify_cb 为 NULL，回调永不触发
// 修复后：初始化为 ssl_verify_cb_thunk，正确路由到 Go 回调
int ssl_verify_cb_thunk(int ok, X509_STORE_CTX *store_ctx) {
	SSL *ssl = X509_STORE_CTX_get_ex_data(store_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());
	if (ssl == NULL) return ok;
	void *go_ssl = SSL_get_ex_data(ssl, get_ssl_idx());
	if (go_ssl == NULL) return ok;
	return go_ssl_verify_cb_thunk(go_ssl, ok, store_ctx);
}

// SSL_CTX verify callback thunk (C-01b fix)
//
// OpenSSL 通过 SSL_CTX_set_verify 注册的验证回调。
// 从 SSL 获取 SSL_CTX，再从 SSL_CTX ex_data 获取 Go *Ctx。
int ssl_ctx_verify_cb_thunk(int ok, X509_STORE_CTX *store_ctx) {
	SSL *ssl = X509_STORE_CTX_get_ex_data(store_ctx,
		SSL_get_ex_data_X509_STORE_CTX_idx());
	if (ssl == NULL) return ok;
	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
	if (ssl_ctx == NULL) return ok;
	void *go_ctx = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	if (go_ctx == NULL) return ok;
	return go_ssl_ctx_verify_cb_thunk(go_ctx, ok, store_ctx);
}

// Ticket key callback thunk (C-02/C-03 fix)
//
// 修复前：X_SSL_CTX_ticket_key_cb_ptr 为 NULL 且签名不匹配
// 修复后：初始化为 ticket_key_cb_thunk，正确 6 参数签名
//
// OpenSSL 签名: int (*)(SSL*, unsigned char*, unsigned char*,
//                       EVP_CIPHER_CTX*, HMAC_CTX*, int)
//
// 符合标准：RFC 5077 (Stateless TLS Session Resumption)
int ticket_key_cb_thunk(SSL *ssl, unsigned char *key_name, unsigned char *iv,
                        EVP_CIPHER_CTX *ctx, HMAC_CTX *hctx, int enc) {
	SSL_CTX *ssl_ctx = SSL_get_SSL_CTX(ssl);
	if (ssl_ctx == NULL) return -1;
	void *go_ctx = SSL_CTX_get_ex_data(ssl_ctx, get_ssl_ctx_idx());
	if (go_ctx == NULL) return -1;
	return go_ticket_key_cb_thunk(go_ctx, key_name, iv, ctx, hctx, enc);
}

// X_init_crypto_thunks 初始化 crypto 包中的回调 thunk 指针
// 由 Go init() 调用，将 sni.c 中的 thunk 注册到 crypto/shim.c 的静态变量
//
// 跨 CGO 编译单元链接：sni.c (根包) 通过 extern 调用 crypto/shim.c 中定义的 setter 函数
// 链接器在最终链接时解析这些符号（两个 .c 编译后的 .o 都链接到同一可执行文件）

// crypto/shim.c 中定义的 setter 函数（extern 声明，链接时解析）
extern void X_set_ssl_verify_thunk(int (*thunk)(int, X509_STORE_CTX *));
extern void X_set_ssl_ctx_verify_thunk(int (*thunk)(int, X509_STORE_CTX *));
extern void X_set_ticket_key_thunk(int (*thunk)(SSL *, unsigned char *, unsigned char *,
                                                EVP_CIPHER_CTX *, HMAC_CTX *, int));

void X_init_crypto_thunks(void) {
	X_set_ssl_verify_thunk(ssl_verify_cb_thunk);
	X_set_ssl_ctx_verify_thunk(ssl_ctx_verify_cb_thunk);
	X_set_ticket_key_thunk(ticket_key_cb_thunk);
}

// SSL_CTX_set1_curves 是宏 (SSL_CTX_ctrl)，CGo 无法直接调用。
// 封装为函数，用于显式设置 TLS supported_groups。
int X_SSL_CTX_set1_curves(SSL_CTX *ctx, const int *curves, size_t len)
{
	return SSL_CTX_set1_curves(ctx, (int *)curves, (size_t)len);
}
