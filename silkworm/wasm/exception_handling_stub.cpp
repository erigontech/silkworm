/*
   Copyright 2024 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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
