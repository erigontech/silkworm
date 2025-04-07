// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <cstdlib>

// Stubs for clang exception handlers on WASM after upgrading Catch2 to version 3.x
// This avoids undefined symbols at linking: https://github.com/WebAssembly/wasi-sdk/issues/329

extern "C" {
void __cxa_allocate_exception() {
    std::abort();
}

void __cxa_throw() {
    std::abort();
}
}
