package tongsuogo

// #include "shim.h"
import "C"

import (
	"runtime/cgo"
	"unsafe"
)

// handleToPtr converts a cgo.Handle to unsafe.Pointer for passing to
// C ex_data APIs (SSL_set_ex_data, SSL_CTX_set_ex_data).
//
// Uses C helper X_cgo_handle_to_ptr to perform the integer-to-pointer
// conversion in C, avoiding Go vet's false positive on
// unsafe.Pointer(uintptr(...)). cgo.Handle is a uintptr (integer index
// into the runtime's handle table), not a Go pointer. The round-trip
// through C is safe because the value is an opaque integer stored and
// returned unchanged by OpenSSL ex_data.
func handleToPtr(h cgo.Handle) unsafe.Pointer {
	return C.X_cgo_handle_to_ptr(C.intptr_t(h))
}

// ptrToHandle converts an unsafe.Pointer from C callback arguments back
// to a cgo.Handle.
func ptrToHandle(p unsafe.Pointer) cgo.Handle {
	return cgo.Handle(C.X_cgo_ptr_to_handle(p))
}
