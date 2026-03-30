package tongsuogo

// This file provides safe helpers for converting between cgo.Handle and
// unsafe.Pointer. cgo.Handle is a uintptr (integer) that represents a Go
// value. The conversion unsafe.Pointer(uintptr(handle)) is safe because:
//   1. cgo.Handle is not a Go pointer, it's an integer index into the
//      runtime's handle table.
//   2. The value is stored in OpenSSL ex_data and returned unchanged by
//      C callbacks, then converted back via ptrToHandle.
//   3. This is the standard pattern documented in Go's cgo documentation
//      for passing Go values through C code.
//
// go vet flags this as "possible misuse of unsafe.Pointer" because it
// cannot prove safety statically. This is a known false positive for
// the cgo.Handle pattern.

import (
	"runtime/cgo"
	"unsafe"
)

// handleToPtr converts a cgo.Handle to unsafe.Pointer for passing to
// C ex_data APIs (SSL_set_ex_data, SSL_CTX_set_ex_data).
//
// NOTE: go vet flags this as "possible misuse of unsafe.Pointer" — this is
// a known false positive. cgo.Handle is uintptr (an integer index), not a
// Go pointer. The round-trip through C is safe because the value is an
// opaque integer stored and returned unchanged by OpenSSL ex_data.
func handleToPtr(h cgo.Handle) unsafe.Pointer {
	return unsafe.Pointer(uintptr(h))
}

// ptrToHandle converts an unsafe.Pointer from C callback arguments back
// to a cgo.Handle.
func ptrToHandle(p unsafe.Pointer) cgo.Handle {
	return cgo.Handle(uintptr(p))
}
