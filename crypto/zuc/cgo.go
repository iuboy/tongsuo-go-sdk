//go:build !static
// +build !static

package zuc

// #cgo CFLAGS: -I${SRCDIR}/../../include -I/opt/local/tongsuo/include
// #cgo LDFLAGS: -lcrypto
import "C"
