package main

// #cgo LDFLAGS: -lsilkworm_capi
// #cgo LDFLAGS: -L${SRCDIR}/../../../build/silkworm/capi
// #cgo LDFLAGS: -Wl,-rpath ${SRCDIR}/../../../build/silkworm/capi
// #cgo CFLAGS: -I${SRCDIR}/../../../silkworm/capi
// #include "silkworm.h"
import "C"

import "fmt"
import "os"

func main() {
	var handle C.SilkwormHandle
	settings := &C.struct_SilkwormSettings{}
	if C.silkworm_init(&handle, settings) != C.SILKWORM_OK {
		fmt.Fprintln(os.Stderr, "silkworm_init failed")
		return
	}
	if C.silkworm_fini(handle) != C.SILKWORM_OK {
		fmt.Fprintln(os.Stderr, "silkworm_fini failed")
		return
	}
}
