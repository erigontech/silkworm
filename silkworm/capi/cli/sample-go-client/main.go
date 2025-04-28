package main

// #cgo LDFLAGS: -lsilkworm_capi
// #cgo LDFLAGS: -L${SRCDIR}/../../../../build/silkworm/capi
// #cgo LDFLAGS: -Wl,-rpath ${SRCDIR}/../../../../build/silkworm/capi
// #cgo CFLAGS: -I${SRCDIR}/../../../../build/silkworm/capi/include
/*
#include "silkworm.h"
#include <stdlib.h>
#include <string.h>

static bool go_string_copy(_GoString_ s, char *dest, size_t size) {
	size_t len = _GoStringLen(s);
	if (len >= size) return false;
	const char *src = _GoStringPtr(s);
	strncpy(dest, src, len);
	dest[len] = '\0';
	return true;
}
*/
import "C"

import "fmt"
import "os"

func main() {
	dataDirPath := os.Getenv("HOME")
	libMdbxVersion := C.GoString(C.silkworm_libmdbx_version())

	var handle C.SilkwormHandle
	settings := &C.struct_SilkwormSettings{}
	if !C.go_string_copy(dataDirPath, &settings.data_dir_path[0], C.SILKWORM_PATH_SIZE) {
		fmt.Fprintln(os.Stderr, "silkworm.New failed to copy dataDirPath")
		os.Exit(1)
	}
	if !C.go_string_copy(libMdbxVersion, &settings.libmdbx_version[0], C.SILKWORM_GIT_VERSION_SIZE) {
		fmt.Fprintln(os.Stderr, "silkworm.New failed to copy libMdbxVersion")
		os.Exit(2)
	}

	initResult := C.silkworm_init(&handle, settings)
	if initResult != C.SILKWORM_OK {
		fmt.Fprintln(os.Stderr, "silkworm_init failed:", initResult)
		os.Exit(int(initResult))
	}

	finiResult := C.silkworm_fini(handle)
	if finiResult != C.SILKWORM_OK {
		fmt.Fprintln(os.Stderr, "silkworm_fini failed:", finiResult)
		os.Exit(int(finiResult))
	}

	os.Exit(0)
}
