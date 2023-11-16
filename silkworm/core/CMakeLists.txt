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

find_package(Microsoft.GSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(tl-expected REQUIRED)

if(MSVC)
  add_compile_options(/EHsc)
else()
  add_compile_options(-fno-exceptions)
endif()

if(SILKWORM_CLANG_TIDY)
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY};-warnings-as-errors=*")
endif()

file(
  GLOB_RECURSE
  SILKWORM_CORE_SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.hpp"
  "*.c"
  "*.h"
)
list(FILTER SILKWORM_CORE_SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SILKWORM_CORE_SRC EXCLUDE REGEX "_benchmark\\.cpp$")

add_library(silkworm_core ${SILKWORM_CORE_SRC})
target_include_directories(silkworm_core PUBLIC ${SILKWORM_MAIN_DIR})

set(SILKWORM_CORE_PUBLIC_LIBS
    ethash::ethash
    evmc
    evmone
    intx::intx
    Microsoft.GSL::GSL
    nlohmann_json::nlohmann_json
    secp256k1
    tl::expected
)
set(SILKWORM_CORE_PRIVATE_LIBS ff blst)

if(SILKWORM_CORE_USE_ABSEIL)
  find_package(absl REQUIRED)
  list(APPEND SILKWORM_CORE_PUBLIC_LIBS absl::flat_hash_map absl::flat_hash_set)
  target_compile_definitions(silkworm_core PUBLIC SILKWORM_CORE_USE_ABSEIL)
endif()

target_link_libraries(
  silkworm_core
  PUBLIC ${SILKWORM_CORE_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_CORE_PRIVATE_LIBS}
)
