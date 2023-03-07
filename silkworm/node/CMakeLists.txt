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
find_package(asio-grpc REQUIRED)
if(CONAN_PACKAGE_MANAGER)
  find_package(Boost REQUIRED container thread)
else()
  find_package(Boost CONFIG REQUIRED container thread)
endif()
find_package(nlohmann_json REQUIRED)
find_package(gRPC REQUIRED)

# Generate source files containing snapshot TOML files as binary data
set(SILKWORM_EMBED embed)
find_package(CLI11 REQUIRED)
add_executable(${SILKWORM_EMBED} ${SILKWORM_MAIN_DIR}/cmd/embed.cpp)
target_link_libraries(${SILKWORM_EMBED} PRIVATE CLI11::CLI11 Boost::headers)

set(SILKWORM_TOML_SRC_DIR "${SILKWORM_MAIN_DIR}/third_party/erigon-snapshot")
set(SILKWORM_TOML_SRC
        ${SILKWORM_TOML_SRC_DIR}/bor-mainnet.toml
        ${SILKWORM_TOML_SRC_DIR}/bsc.toml
        ${SILKWORM_TOML_SRC_DIR}/gnosis.toml
        ${SILKWORM_TOML_SRC_DIR}/goerli.toml
        ${SILKWORM_TOML_SRC_DIR}/mainnet.toml
        ${SILKWORM_TOML_SRC_DIR}/mumbai.toml
        ${SILKWORM_TOML_SRC_DIR}/ropsten.toml
        ${SILKWORM_TOML_SRC_DIR}/sepolia.toml)
set(SILKWORM_TOML_CPP_SRC_DIR "${SILKWORM_MAIN_SRC_DIR}/node/snapshot/config")
set(SILKWORM_TOML_CPP_SRC
        ${SILKWORM_TOML_CPP_SRC_DIR}/bor_mainnet.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/bsc.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/gnosis.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/goerli.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/mainnet.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/mumbai.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/ropsten.cpp
        ${SILKWORM_TOML_CPP_SRC_DIR}/sepolia.cpp)

add_custom_command(
        OUTPUT "${SILKWORM_TOML_CPP_SRC}"
        COMMAND "${SILKWORM_EMBED}"
        ARGS -i "${SILKWORM_TOML_SRC_DIR}" -o "${SILKWORM_TOML_CPP_SRC_DIR}" -e ".toml" -s "toml"
        DEPENDS "${SILKWORM_EMBED}"
)

add_custom_target(generate_toml DEPENDS "${SILKWORM_TOML_SRC}" "${SILKWORM_EMBED}")

file(GLOB_RECURSE SILKWORM_NODE_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h" "*.cc")
list(FILTER SILKWORM_NODE_SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SILKWORM_NODE_SRC EXCLUDE REGEX "_benchmark\\.cpp$")

set(SILKWORM_INTERFACE_SRC
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.grpc.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.grpc.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/p2psentry/sentry.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.grpc.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.grpc.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.grpc.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.grpc.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.pb.h
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/types/types.pb.cc
        ${SILKWORM_MAIN_SRC_DIR}/interfaces/types/types.pb.h)

add_library(silkworm_node ${SILKWORM_NODE_SRC} ${SILKWORM_INTERFACE_SRC} ${SILKWORM_TOML_CPP_SRC})

add_dependencies(silkworm_node generate_ethbackend_grpc generate_kv_grpc generate_sentry_grpc generate_toml)

set_source_files_properties(${SILKWORM_INTERFACE_SRC} PROPERTIES GENERATED TRUE)
if(NOT MSVC)
  set_source_files_properties(${SILKWORM_INTERFACE_SRC} PROPERTIES COMPILE_FLAGS -Wno-sign-conversion)
endif(NOT MSVC)

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers
# See https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
  target_compile_definitions(silkworm_node PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

target_include_directories(silkworm_node PUBLIC
        ${SILKWORM_MAIN_DIR}
        ${SILKWORM_MAIN_SRC_DIR}/interfaces
        ${SILKWORM_MAIN_DIR}/third_party/magic_enum/include
        ${SILKWORM_MAIN_DIR}/third_party/libtorrent/include
        ${SILKWORM_MAIN_DIR}/third_party/tomlplusplus)

set(SILKWORM_NODE_PUBLIC_LIBS silkworm_core mdbx-static absl::flat_hash_map absl::flat_hash_set absl::btree roaring
        nlohmann_json::nlohmann_json gRPC::grpc++ protobuf::libprotobuf Boost::container Boost::thread asio-grpc::asio-grpc
        torrent-rasterbar)
set(SILKWORM_NODE_PRIVATE_LIBS cborcpp evmone)

if(MSVC)
  list(APPEND SILKWORM_NODE_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm_node PUBLIC ${SILKWORM_NODE_PUBLIC_LIBS} PRIVATE ${SILKWORM_NODE_PRIVATE_LIBS})
