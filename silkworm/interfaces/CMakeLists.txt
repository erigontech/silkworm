#[[
   Copyright 2023 The Silkworm Authors

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

include(generate_grpc.cmake)

find_package(absl REQUIRED)
find_package(gRPC REQUIRED)
find_package(Protobuf REQUIRED)

unset(CMAKE_CXX_CLANG_TIDY)

set(SILKWORM_INTERFACE_SRC "")
list(APPEND SILKWORM_INTERFACE_SRC "${TYPES_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${EXECUTION_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${SENTRY_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${KV_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${ETHBACKEND_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${BOR_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${MINING_SOURCES_SYMLINK}")
list(APPEND SILKWORM_INTERFACE_SRC "${TXPOOL_SOURCES_SYMLINK}")

add_library(silkworm_interfaces "${SILKWORM_INTERFACE_SRC}")

# cmake-format: off
add_dependencies(
  silkworm_interfaces
  generate_types_proto_symlink
  generate_execution_grpc_symlink
  generate_sentry_grpc_symlink
  generate_remote_grpc_symlink
  generate_txpool_grpc_symlink
)
# cmake-format: on

if(NOT MSVC)
  target_compile_options(silkworm_interfaces PRIVATE -Wno-sign-conversion)

  check_cxx_compiler_flag("-Wno-deprecated-pragma" HAS_NO_DEPRECATED_PRAGMA)
  if(HAS_NO_DEPRECATED_PRAGMA)
    target_compile_options(silkworm_interfaces PRIVATE -Wno-deprecated-pragma)
  endif()
endif(NOT MSVC)

target_include_directories(silkworm_interfaces PUBLIC "${SILKWORM_MAIN_DIR};${CMAKE_CURRENT_SOURCE_DIR}")

# cmake-format: off
set(LIBS_PUBLIC
    absl::log
    absl::strings
    gRPC::grpc++
    protobuf::libprotobuf
)
# cmake-format: on
set(LIBS_PRIVATE "")
if(MSVC)
  list(APPEND LIBS_PRIVATE ntdll.lib)
endif(MSVC)

target_link_libraries(
  silkworm_interfaces
  PUBLIC "${LIBS_PUBLIC}"
  PRIVATE "${LIBS_PRIVATE}"
)
