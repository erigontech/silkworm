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

hunter_add_package(Boost COMPONENTS filesystem)
find_package(Boost CONFIG REQUIRED COMPONENTS filesystem)

hunter_add_package(lmdb)
find_package(liblmdb CONFIG REQUIRED)

hunter_add_package(lmdbxx)
find_package(lmdbxx CONFIG REQUIRED)

hunter_add_package(cryptopp)
find_package(cryptopp CONFIG REQUIRED)

hunter_add_package(Microsoft.GSL)
find_package(Microsoft.GSL CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h")
list(FILTER SILKWORM_SRC EXCLUDE REGEX "_test\.cpp$")

add_compile_definitions(NATIVE_LITTLE_ENDIAN)

if(MSVC)
  add_compile_options(/W4)
endif()

add_library(silkworm ${SILKWORM_SRC})
target_include_directories(silkworm PUBLIC ${CMAKE_SOURCE_DIR})

set(SILKWORM_PUBLIC_LIBS absl::flat_hash_map absl::flat_hash_set
                         liblmdb::lmdb evmc intx::intx ff Microsoft.GSL::GSL
                         lmdbxx::lmdbxx) # PUBLIC lmdbxx since we use its exceptions

set(SILKWORM_PRIVATE_LIBS evmone secp256k1 cryptopp-static ethash::keccak Boost::filesystem)

if(MSVC)
  list(APPEND SILKWORM_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm PUBLIC ${SILKWORM_PUBLIC_LIBS} PRIVATE ${SILKWORM_PRIVATE_LIBS})
