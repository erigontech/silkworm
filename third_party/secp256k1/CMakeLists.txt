#[[
   Copyright 2022 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
]]

add_library(secp256k1 secp256k1/src/secp256k1.c)
if(MSVC)
  target_compile_options(secp256k1 PRIVATE /w) # Not much we can do about warnings
endif()
# cmake-format: off
target_compile_definitions(
  secp256k1
  PUBLIC ECMULT_WINDOW_SIZE=15
         ECMULT_GEN_PREC_BITS=4
         ENABLE_MODULE_ECDH
         ENABLE_MODULE_RECOVERY
)
# cmake-format: on
target_include_directories(
  secp256k1
  PRIVATE secp256k1
  INTERFACE secp256k1/include
)
