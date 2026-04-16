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

package tongsuogo

// #include "shim.h"
import "C"

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/tongsuo-project/tongsuo-go-sdk/crypto"
)

const (
	KeyNameSize = 16
)

// TicketCipherCtx describes the cipher that will be used by the ticket store
// for encrypting the tickets.
type TicketCipherCtx struct {
	Cipher *crypto.Cipher
}

// TicketDigestCtx describes the digest that will be used by the ticket store
// to authenticate the data.
type TicketDigestCtx struct {
	Digest *crypto.Digest
}

// TicketName is an identifier for the key material for a ticket.
type TicketName [KeyNameSize]byte

// TicketKey is the key material for a ticket. If this is lost, forward secrecy
// is lost as it allows decrypting TLS sessions retroactively.
//
// 安全要求（NIST SP 800-57 Part 1 Rev.5 Section 5.3.4）：
//   - 密钥材料在不再使用时必须安全清零
//   - 调用方应在密钥过期或替换后调用 Clear()
type TicketKey struct {
	Name      TicketName
	CipherKey []byte
	HMACKey   []byte
	IV        []byte
}

// Clear 安全清零 TicketKey 中的所有密钥材料。
//
// 必须在密钥过期、替换或不再使用时调用此方法。
// 使用 OPENSSL_cleanse 确保编译器不会优化掉清零操作。
//
// 符合标准：
//   - NIST SP 800-57 Part 1 Rev.5 Section 5.3.4 (Cryptographic Key Destruction)
//   - FIPS 140-2 Section 4.12.0
func (k *TicketKey) Clear() {
	if k == nil {
		return
	}
	crypto.ZeroBytes(k.CipherKey)
	crypto.ZeroBytes(k.HMACKey)
	crypto.ZeroBytes(k.IV)
	for i := range k.Name {
		k.Name[i] = 0
	}
}

// TicketKeyManager is a manager for TicketKeys. It allows one to control the
// lifetime of tickets, causing renewals and expirations for keys that are
// created. Calls to the manager are serialized.
type TicketKeyManager interface {
	// New should create a brand new TicketKey with a new name.
	New() *TicketKey

	// Current should return a key that is still valid.
	Current() *TicketKey

	// Lookup should return a key with the given name, or nil if no name
	// exists.
	Lookup(name TicketName) *TicketKey

	// Expired should return if the key with the given name is expired and
	// should not be used any more.
	Expired(name TicketName) bool

	// ShouldRenew should return if the key is still ok to use for the current
	// session, but we should send a new key for the client.
	ShouldRenew(name TicketName) bool
}

// TicketStore descibes the encryption and authentication methods the tickets
// will use along with a key manager for generating and keeping track of the
// secrets.
type TicketStore struct {
	CipherCtx TicketCipherCtx
	DigestCtx TicketDigestCtx
	Keys      TicketKeyManager
}

const (
	// instruct to do a handshake
	ticketRespRequireHandshake = 0
	// crypto context is set up correctly
	ticketRespSessionOk = 1
	// crypto context is ok, but the ticket should be reissued
	ticketRespRenewSession = 2
	// we had a problem that shouldn't fall back to doing a handshake
	ticketRespError = -1
	// asked to create session crypto context
	ticketReqNewSession = 1
	// asked to load crypto context for a previous session
	ticketReqLookupSession = 0
)

//export go_ticket_key_cb_thunk
func go_ticket_key_cb_thunk(pctx unsafe.Pointer, keyName *C.uchar, iv *C.uchar, cctx *C.EVP_CIPHER_CTX, hctx *C.HMAC_CTX, enc C.int,
) C.int {
	// no panic's allowed. it's super hard to guarantee any state at this point
	// so just abort everything.
	defer func() {
		if err := recover(); err != nil {
			// logger.Critf("openssl: ticket key callback panic'd: %v", err)
			os.Exit(1)
		}
	}()

	ctx := (*Ctx)(pctx)
	store := ctx.ticketStore
	if store == nil {
		// should this be an error condition? it doesn't make sense
		// to be called if we don't have a store I believe, but that's probably
		// not worth aborting the handshake which is what I believe returning
		// an error would do.
		return ticketRespRequireHandshake
	}

	ctx.ticketStoreMu.Lock()
	defer ctx.ticketStoreMu.Unlock()

	switch enc {
	case ticketReqNewSession:
		key := store.Keys.Current()
		if key == nil {
			key = store.Keys.New()
			if key == nil {
				return ticketRespRequireHandshake
			}
		}

		// RFC 5077 Section 4: 验证密钥材料长度
		if len(key.CipherKey) == 0 {
			fmt.Fprintf(os.Stderr, "tongsuo-go-sdk: ticket CipherKey is empty\n")
			return ticketRespRequireHandshake
		}
		if len(key.HMACKey) == 0 {
			fmt.Fprintf(os.Stderr, "tongsuo-go-sdk: ticket HMACKey is empty\n")
			return ticketRespRequireHandshake
		}

		C.memcpy(
			unsafe.Pointer(keyName),
			unsafe.Pointer(&key.Name[0]),
			KeyNameSize)
		// 将 IV 写入 OpenSSL 提供的缓冲区（包含在 ticket 中）
		if iv != nil && len(key.IV) > 0 {
			C.memcpy(
				unsafe.Pointer(iv),
				unsafe.Pointer(&key.IV[0]),
				C.size_t(len(key.IV)))
		}
		C.EVP_EncryptInit_ex(
			cctx,
			(*C.EVP_CIPHER)(store.CipherCtx.Cipher.Ptr()),
			nil,
			(*C.uchar)(&key.CipherKey[0]),
			(*C.uchar)(&key.IV[0]))
		C.HMAC_Init_ex(
			hctx,
			unsafe.Pointer(&key.HMACKey[0]),
			C.int(len(key.HMACKey)),
			(*C.EVP_MD)(store.DigestCtx.Digest.Ptr()),
			nil)

		return ticketRespSessionOk

	case ticketReqLookupSession:
		var name TicketName
		C.memcpy(
			unsafe.Pointer(&name[0]),
			unsafe.Pointer(keyName),
			KeyNameSize)

		key := store.Keys.Lookup(name)
		if key == nil {
			return ticketRespRequireHandshake
		}
		if store.Keys.Expired(name) {
			// 密钥已过期，安全清零密钥材料
			// 符合 NIST SP 800-57 Part 1 Rev.5 Section 5.3.4
			key.Clear()
			return ticketRespRequireHandshake
		}

		C.EVP_DecryptInit_ex(
			cctx,
			(*C.EVP_CIPHER)(store.CipherCtx.Cipher.Ptr()),
			nil,
			(*C.uchar)(&key.CipherKey[0]),
			iv)
		C.HMAC_Init_ex(
			hctx,
			unsafe.Pointer(&key.HMACKey[0]),
			C.int(len(key.HMACKey)),
			(*C.EVP_MD)(store.DigestCtx.Digest.Ptr()),
			nil)

		if store.Keys.ShouldRenew(name) {
			return ticketRespRenewSession
		}

		return ticketRespSessionOk

	default:
		return ticketRespError
	}
}

// SetTicketStore sets the ticket store for the context so that clients can do
// ticket based session resumption. If the store is nil, the
func (c *Ctx) SetTicketStore(store *TicketStore) {
	c.ticketStore = store

	if store == nil {
		C.X_SSL_CTX_set_tlsext_ticket_key_cb(c.ctx, nil)
	} else {
		// 获取回调函数指针并解引用
		cbPtr := C.X_SSL_CTX_ticket_key_cb()
		C.X_SSL_CTX_set_tlsext_ticket_key_cb(c.ctx,
			*cbPtr)
	}
}
