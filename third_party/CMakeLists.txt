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

# please keep the list sorted
add_subdirectory(blst)
add_subdirectory(ethash)
add_subdirectory(gmp)
add_subdirectory(intx) # depends on gmp
add_subdirectory(libff) # depends on gmp
add_subdirectory(secp256k1)

add_subdirectory(evmone) # depends on ethash, intx

# please keep the list sorted
if(NOT SILKWORM_CORE_ONLY)
  add_subdirectory(cbor-cpp)
  add_subdirectory(cpp-base64)
  add_subdirectory(erigon-mdbx-go)
  add_subdirectory(glaze)
  add_subdirectory(libdeflate)
  add_subdirectory(sais-lite)
  add_subdirectory(stbrumme-crc32)
  add_subdirectory(stbrumme-keccak)
  add_subdirectory(stun-msg)
  add_subdirectory(llvm)
endif()
