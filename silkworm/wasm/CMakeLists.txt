# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

add_executable(silkworm.wasm silkworm_wasm_api.cpp)
target_link_libraries(silkworm.wasm silkworm_core)
target_compile_options(silkworm.wasm PRIVATE -fno-exceptions)

# See https://lld.llvm.org/WebAssembly.html
target_link_options(silkworm.wasm PRIVATE -Wl,--export-dynamic)
