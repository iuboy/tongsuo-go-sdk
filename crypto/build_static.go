// Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
//
// Licensed under the Apache License 2.0 (the "License").  You may not use
// this file except in License.  You can obtain a copy in the source
// distribution or at
// https://github.com/Tongsuo-Project/tongsuo-go-sdk/blob/main/LICENSE

//go:build static
// +build static

package crypto

// #cgo CFLAGS: -I${SRCDIR}/../include
// #cgo LDFLAGS: -lssl -lcrypto
import "C"
