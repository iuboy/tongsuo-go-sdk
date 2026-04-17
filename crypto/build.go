// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in compliance with the License.  You can obtain a copy
// in the file LICENSE in the source distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

//go:build !static
// +build !static

package crypto

// #cgo CFLAGS: -I${SRCDIR}/../include
// #cgo linux CFLAGS: -I${SRCDIR}/../include -I/opt/local/tongsuo/include
// #cgo linux LDFLAGS: -L/opt/local/tongsuo/lib -lssl -lcrypto
// #cgo darwin CFLAGS: -I${SRCDIR}/../include -I/opt/local/tongsuo/include
// #cgo darwin LDFLAGS: -L/opt/local/tongsuo/lib -lssl -lcrypto
// #cgo windows CFLAGS: -DWIN32_LEAN_AND_MEAN -I${SRCDIR}/../include -I/opt/local/tongsuo/include
// #cgo windows LDFLAGS: -L/opt/local/tongsuo/lib -lssl -lcrypto
import "C"
