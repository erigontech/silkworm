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

find_package(absl REQUIRED)
find_package(Boost CONFIG REQUIRED container thread)
find_package(gRPC REQUIRED)

file(GLOB_RECURSE SILKWORM_SYNC_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h" "*.cc")
list(FILTER SILKWORM_SYNC_SRC EXCLUDE REGEX "_test\\.cpp$")

set(SILKWORM_INTERFACE_SRC
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.grpc.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.grpc.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/types/types.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/types/types.pb.h)

add_library(silkworm_sync ${SILKWORM_SYNC_SRC} ${SILKWORM_INTERFACE_SRC})

add_dependencies(silkworm_sync generate_sentry_grpc)

set_source_files_properties(${SILKWORM_INTERFACE_SRC} PROPERTIES GENERATED TRUE)
if(NOT MSVC)
  set_source_files_properties(${SILKWORM_INTERFACE_SRC} PROPERTIES COMPILE_FLAGS -Wno-sign-conversion)
endif(NOT MSVC)

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers
# See https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
  target_compile_definitions(silkworm_sync PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

target_include_directories(silkworm_sync PUBLIC
        ${SILKWORM_MAIN_DIR}
        ${SILKWORM_MAIN_SRC_DIR}/interfaces
        ${SILKWORM_MAIN_DIR}/third_party/magic_enum/include)

set(SILKWORM_SYNC_PUBLIC_LIBS silkworm_node silkworm_core mdbx-static absl::flat_hash_map absl::flat_hash_set absl::btree
        gRPC::grpc++ protobuf::libprotobuf)
set(SILKWORM_SYNC_PRIVATE_LIBS cborcpp evmone)

if(MSVC)
  list(APPEND SILKWORM_SYNC_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm_sync PUBLIC ${SILKWORM_SYNC_PUBLIC_LIBS} PRIVATE ${SILKWORM_SYNC_PRIVATE_LIBS})
