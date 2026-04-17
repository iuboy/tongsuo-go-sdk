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

package crypto

/*
#include "shim.h"

#ifndef X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
#define X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT	0x1
#define X509_CHECK_FLAG_NO_WILDCARDS	0x2
#endif
*/
import "C"

import (
	"net"
	"unsafe"
)

type CheckFlags int

const (
	AlwaysCheckSubject CheckFlags = C.X509_CHECK_FLAG_ALWAYS_CHECK_SUBJECT
	NoWildcards        CheckFlags = C.X509_CHECK_FLAG_NO_WILDCARDS
)

// CheckHost checks that the X509 certificate is signed for the provided
// host name. See http://www.openssl.org/docs/crypto/X509_check_host.html for
// more. Note that CheckHost does not check the IP field. See VerifyHostname.
// Specifically returns ValidationError if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) CheckHost(host string, flags CheckFlags) error {
	chost := C.CString(host)
	defer C.free(unsafe.Pointer(chost))

	rv := C.X_X509_check_host(c.x, chost, C.size_t(len(host)),
		C.uint(flags))
	if rv > 0 {
		return nil
	}
	if rv == 0 {
		return ErrMatchFailed
	}
	if rv == -2 {
		return ErrInputInvalid
	}

	return ErrInternalError
}

// CheckEmail checks that the X509 certificate is signed for the provided
// email address. See http://www.openssl.org/docs/crypto/X509_check_host.html
// for more.
// Specifically returns ValidationError if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) CheckEmail(email string, flags CheckFlags) error {
	cemail := C.CString(email)
	defer C.free(unsafe.Pointer(cemail))
	rv := C.X_X509_check_email(c.x, cemail, C.size_t(len(email)),
		C.uint(flags))
	if rv > 0 {
		return nil
	}
	if rv == 0 {
		return ErrMatchFailed
	}
	if rv == -2 {
		return ErrInputInvalid
	}

	return ErrInternalError
}

// CheckIP checks that the X509 certificate is signed for the provided
// IP address. See http://www.openssl.org/docs/crypto/X509_check_host.html
// for more.
// Specifically returns ValidationError if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) CheckIP(ip net.IP, flags CheckFlags) error {
	// X509_check_ip will fail to validate the 16-byte representation of an IPv4
	// address, so convert to the 4-byte representation.
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	cip := unsafe.Pointer(&ip[0])
	rv := C.X_X509_check_ip(c.x, (*C.uchar)(cip), C.size_t(len(ip)),
		C.uint(flags))
	if rv > 0 {
		return nil
	}
	if rv == 0 {
		return ErrMatchFailed
	}
	if rv == -2 {
		return ErrInputInvalid
	}

	return ErrInternalError
}

// VerifyHostname is a combination of CheckHost and CheckIP. If the provided
// hostname looks like an IP address, it will be checked as an IP address,
// otherwise it will be checked as a hostname.
// Specifically returns ValidationError if the Certificate didn't match but
// there was no internal error.
func (c *Certificate) VerifyHostname(host string) error {
	var ip net.IP
	if len(host) >= 3 && host[0] == '[' && host[len(host)-1] == ']' {
		ip = net.ParseIP(host[1 : len(host)-1])
	} else {
		ip = net.ParseIP(host)
	}
	if ip != nil {
		return c.CheckIP(ip, 0)
	}
	return c.CheckHost(host, 0)
}
