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

hunter_add_package(Snappy)

find_package(absl CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED thread)
find_package(gRPC CONFIG REQUIRED)
find_package(Microsoft.GSL CONFIG REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Snappy CONFIG REQUIRED)

get_filename_component(MAIN_DIR ../ ABSOLUTE)

set(SRC "")
file(GLOB_RECURSE SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h" "*.cc")
list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")

set(GRPC_SRC "")
set(GRPC_SRC_DIR "${MAIN_DIR}/interfaces/p2psentry")
file(GLOB GRPC_SRC CONFIGURE_DEPENDS "${GRPC_SRC_DIR}/*.h" "${GRPC_SRC_DIR}/*.cc")
list(PREPEND GRPC_SRC "${MAIN_DIR}/interfaces/types/types.pb.cc")
list(PREPEND GRPC_SRC "${MAIN_DIR}/interfaces/types/types.pb.h")
list(PREPEND SRC ${GRPC_SRC})

list(PREPEND SRC "${MAIN_DIR}/third_party/stbrumme-keccak/keccak.cpp")

add_library(${TARGET} ${SRC})

add_dependencies(${TARGET} silkworm_node generate_sentry_grpc)

set_source_files_properties(${GRPC_SRC} PROPERTIES GENERATED TRUE)
if(NOT MSVC)
  set_source_files_properties(${GRPC_SRC} PROPERTIES COMPILE_FLAGS -Wno-sign-conversion)
endif(NOT MSVC)

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers
# See https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
    target_compile_definitions(${TARGET} PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

target_include_directories(${TARGET} PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}
  "${MAIN_DIR}/interfaces"
  "${MAIN_DIR}/third_party/stbrumme-keccak"
)

set(LIBS
  Boost::thread
  gRPC::grpc++
  Microsoft.GSL::GSL
  protobuf::libprotobuf
  OpenSSL::Crypto
  Snappy::snappy

  silkpre
  silkworm_core
  silkworm_node
  silkworm-buildinfo
)

if(MSVC)
  list(APPEND LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(${TARGET} PRIVATE ${LIBS})
