package main

/*
//#cgo CXXFLAGS: -std=c++14
#cgo CFLAGS: -I/mnt/c/Users/miche/WorkingArea/Torquem/silkworm/silkworm/api
#cgo LDFLAGS: -L/mnt/c/Users/miche/WorkingArea/Torquem/silkworm/cmake-build-debug-vs-conan/cmd/api/Debug -lexecute_cpp -lstdc++ -ldl

#include "silkworm_api.h"

typedef int (*silkworm_init_func)(SilkwormHandle** handle);

int call_silkworm_init_func(void* func_ptr, SilkwormHandle** handle) {
    return ((silkworm_init_func)func_ptr)(handle);
}

typedef int (*silkworm_fini_func)(SilkwormHandle** handle);

int call_silkworm_fini_func(void* func_ptr, SilkwormHandle** handle) {
    return ((silkworm_fini_func)func_ptr)(handle);
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Silkworm struct {
	libHandle unsafe.Pointer
	instance  *C.SilkwormHandle
	initFunc  unsafe.Pointer
	finiFunc  unsafe.Pointer
}

func LoadSilkworm(silkworm *Silkworm, dllPath string) {
	silkworm.libHandle, _ = OpenDynLibrary(dllPath)
	if silkworm.libHandle == nil {
		panic(fmt.Errorf("failed to load silkworm dynamic library"))
	}

	silkworm.initFunc, _ = LoadFunction(silkworm.libHandle, "silkworm_init")
	silkworm.finiFunc, _ = LoadFunction(silkworm.libHandle, "silkworm_fini")

	if silkworm.initFunc == nil || silkworm.finiFunc == nil {
		panic(fmt.Errorf("failed to find all silkworm functions"))
	}
}

func (silkworm *Silkworm) Init() {
	C.call_silkworm_init_func(silkworm.initFunc, &silkworm.instance)
}

func (silkworm *Silkworm) Fini() {
	C.call_silkworm_fini_func(silkworm.finiFunc, &silkworm.instance)
}
