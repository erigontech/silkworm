#[[
   Copyright 2020 The Silkworm Authors

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

find_package(absl CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS filesystem)
find_package(cryptopp CONFIG REQUIRED)
find_package(liblmdb CONFIG REQUIRED)
find_package(Microsoft.GSL CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h")
list(FILTER SILKWORM_SRC EXCLUDE REGEX "_test\.cpp$")

add_library(silkworm ${SILKWORM_SRC})
target_include_directories(silkworm PUBLIC ${CMAKE_SOURCE_DIR})

set(SILKWORM_PUBLIC_LIBS absl::flat_hash_map absl::flat_hash_set absl::btree Boost::filesystem
                         liblmdb::lmdb evmc intx::intx ff Microsoft.GSL::GSL)

set(SILKWORM_PRIVATE_LIBS evmone secp256k1 cryptopp-static ethash::keccak cborcpp)

if(MSVC)
  list(APPEND SILKWORM_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm PUBLIC ${SILKWORM_PUBLIC_LIBS} PRIVATE ${SILKWORM_PRIVATE_LIBS})
