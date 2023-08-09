package main

/*
// compiler flags:
//#cgo CXXFLAGS: -std=c++14
#cgo CFLAGS: -I${SRCDIR}/../../../silkworm/api
// linker flags: it is better to specify LDFLAGS at build time because the silkworm build dir is user specific
// #cgo LDFLAGS: -L${SRCDIR}/../../../build_debug/silkworm/api -lsilkworm_api -lstdc++ -ldl

#include "silkworm_api.h"

#include <stdlib.h>

typedef int (*silkworm_init_func)(SilkwormHandle** handle);

int call_silkworm_init_func(void* func_ptr, SilkwormHandle** handle) {
    return ((silkworm_init_func)func_ptr)(handle);
}

typedef int (*silkworm_fini_func)(SilkwormHandle* handle);

int call_silkworm_fini_func(void* func_ptr, SilkwormHandle* handle) {
    return ((silkworm_fini_func)func_ptr)(handle);
}

typedef int (*silkworm_add_snapshot_func)(SilkwormHandle* handle, struct SilkwormChainSnapshot* snapshot);

int call_silkworm_add_snapshot_func(void* func_ptr, SilkwormHandle* handle, struct SilkwormChainSnapshot* snapshot) {
    return ((silkworm_add_snapshot_func)func_ptr)(handle, snapshot);
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Silkworm struct {
	libHandle   unsafe.Pointer
	instance    *C.SilkwormHandle
	initFunc    unsafe.Pointer
	finiFunc    unsafe.Pointer
	addSnapshot unsafe.Pointer
}

func LoadSilkworm(silkworm *Silkworm, dllPath string) {
	silkworm.libHandle, _ = OpenDynLibrary(dllPath)
	if silkworm.libHandle == nil {
		panic(fmt.Errorf("failed to load silkworm dynamic library"))
	}

	silkworm.initFunc, _ = LoadFunction(silkworm.libHandle, "silkworm_init")
	silkworm.finiFunc, _ = LoadFunction(silkworm.libHandle, "silkworm_fini")
	silkworm.addSnapshot, _ = LoadFunction(silkworm.libHandle, "silkworm_add_snapshot")

	if silkworm.initFunc == nil || silkworm.finiFunc == nil {
		panic(fmt.Errorf("failed to find all silkworm functions"))
	}
}

func (silkworm *Silkworm) Init() {
	C.call_silkworm_init_func(silkworm.initFunc, &silkworm.instance)
}

func (silkworm *Silkworm) Fini() {
	C.call_silkworm_fini_func(silkworm.finiFunc, silkworm.instance)
}

func (silkworm *Silkworm) AddSnapshot(snapshot *C.struct_SilkwormChainSnapshot) {
	C.call_silkworm_add_snapshot_func(silkworm.addSnapshot, silkworm.instance, snapshot)
}
