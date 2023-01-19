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

find_package(absl CONFIG REQUIRED)
find_package(asio-grpc CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED container thread)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
find_package(Snappy CONFIG REQUIRED)

get_filename_component(SILKWORM_MAIN_DIR ../ ABSOLUTE)

file(GLOB_RECURSE SILKWORM_LIGHTCLIENT_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h" "*.cc")
list(FILTER SILKWORM_LIGHTCLIENT_SRC EXCLUDE REGEX "_test\\.cpp$")

set(SILKWORM_LIGHTCLIENT_INTERFACE_SRC
        ${SILKWORM_MAIN_DIR}/interfaces/p2psentinel/sentinel.grpc.pb.cc
        ${SILKWORM_MAIN_DIR}/interfaces/p2psentinel/sentinel.grpc.pb.h
        ${SILKWORM_MAIN_DIR}/interfaces/p2psentinel/sentinel.pb.cc
        ${SILKWORM_MAIN_DIR}/interfaces/p2psentinel/sentinel.pb.h
        ${SILKWORM_MAIN_DIR}/interfaces/types/types.pb.cc
        ${SILKWORM_MAIN_DIR}/interfaces/types/types.pb.h)

add_library(silkworm_lightclient ${SILKWORM_LIGHTCLIENT_SRC} ${SILKWORM_LIGHTCLIENT_INTERFACE_SRC})

add_dependencies(silkworm_lightclient generate_ethbackend_grpc generate_kv_grpc generate_sentry_grpc)

set_source_files_properties(${SILKWORM_LIGHTCLIENT_INTERFACE_SRC} PROPERTIES GENERATED TRUE)
if(NOT MSVC)
  set_source_files_properties(${SILKWORM_LIGHTCLIENT_INTERFACE_SRC} PROPERTIES COMPILE_FLAGS -Wno-sign-conversion)
endif(NOT MSVC)

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers
# See https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
  target_compile_definitions(silkworm_lightclient PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

target_include_directories(silkworm_lightclient PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${SILKWORM_MAIN_DIR}/interfaces
        ${SILKWORM_MAIN_DIR}/third_party/cpp_ssz/include
        ${SILKWORM_MAIN_DIR}/third_party/magic_enum/include)

set(SILKWORM_LIGHTCLIENT_PUBLIC_LIBS silkworm_core silkworm_node mdbx-static absl::flat_hash_map absl::flat_hash_set absl::btree roaring
        nlohmann_json::nlohmann_json gRPC::grpc++ protobuf::libprotobuf Boost::container Boost::thread asio-grpc::asio-grpc
        Snappy::snappy
        silkworm_sentry) # Temporary TBR moving modules from sentry to node
set(SILKWORM_LIGHTCLIENT_PRIVATE_LIBS "")

if(MSVC)
  list(APPEND SILKWORM_LIGHTCLIENT_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm_lightclient PUBLIC ${SILKWORM_LIGHTCLIENT_PUBLIC_LIBS} PRIVATE ${SILKWORM_LIGHTCLIENT_PRIVATE_LIBS})
