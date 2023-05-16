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

set(TARGET silkworm_sentry)

if(NOT CONAN_PACKAGE_MANAGER)
  hunter_add_package(Snappy)
endif()

find_package(absl REQUIRED)
if(CONAN_PACKAGE_MANAGER)
  find_package(Boost REQUIRED thread)
else()
  find_package(Boost CONFIG REQUIRED thread)
endif()
find_package(gRPC REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Snappy REQUIRED)

set(SRC "")
file(
  GLOB_RECURSE
  SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.hpp"
  "*.c"
  "*.h"
  "*.cc"
)
list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")

list(PREPEND SRC "${SILKWORM_MAIN_DIR}/third_party/stbrumme-keccak/keccak.cpp")
list(PREPEND SRC "${SILKWORM_MAIN_DIR}/third_party/stbrumme-crc32/Crc32.cpp")

add_library(${TARGET} ${SRC})

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers See
# https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
  target_compile_definitions(${TARGET} PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

# cmake-format: off
target_include_directories(
  ${TARGET}
  PUBLIC "${SILKWORM_MAIN_DIR}"
         "${SILKWORM_MAIN_DIR}/third_party/stbrumme-keccak"
         "${SILKWORM_MAIN_DIR}/third_party/stbrumme-crc32"
)
# cmake-format: on

set(LIBS_PRIVATE
    gRPC::grpc++
    protobuf::libprotobuf
    OpenSSL::Crypto
    Snappy::snappy
    silkworm_core
    silkworm_interfaces
    silkworm-buildinfo
)
if(MSVC)
  list(APPEND LIBS_PRIVATE ntdll.lib)
endif(MSVC)

# cmake-format: off
set(LIBS_PUBLIC
    Boost::thread
    Microsoft.GSL::GSL
    silkworm_infra
)
# cmake-format: on

target_link_libraries(
  ${TARGET}
  PUBLIC "${LIBS_PUBLIC}"
  PRIVATE "${LIBS_PRIVATE}"
)
