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

find_package(absl REQUIRED)
find_package(asio-grpc REQUIRED)
if(CONAN_PACKAGE_MANAGER)
    find_package(Boost REQUIRED container thread)
else()
    find_package(Boost CONFIG REQUIRED container thread)
endif()
find_package(intx REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)

set(SILKWORM_INTERFACE_SRC
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.grpc.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.grpc.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/ethbackend.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.grpc.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.grpc.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/remote/kv.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/mining.grpc.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/mining.grpc.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/mining.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/mining.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/mining_mock.grpc.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/txpool.grpc.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/txpool.grpc.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/txpool.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/txpool.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/txpool/txpool_mock.grpc.pb.h
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/types/types.pb.cc
    ${SILKWORM_MAIN_SRC_DIR}/interfaces/types/types.pb.h)

set_source_files_properties(${SILKWORM_INTERFACE_SRC} PROPERTIES GENERATED TRUE)
if(NOT MSVC)
    set_source_files_properties(${SILKWORM_INTERFACE_SRC} PROPERTIES COMPILE_FLAGS -Wno-sign-conversion)
endif(NOT MSVC)

# Silkrpc library
file(GLOB_RECURSE SILKRPC_SRC CONFIGURE_DEPENDS "*.cpp" "*.cc" "*.hpp" "*.c" "*.h")
list(FILTER SILKRPC_SRC EXCLUDE REGEX "main\\.cpp$|_test\\.cpp$|\\.pb\\.cc|\\.pb\\.h")

set(SILKRPC_LIBRARIES
    absl::flat_hash_map
    absl::flat_hash_set
    absl::btree
    asio-grpc::asio-grpc
    intx::intx
    jwt-cpp::jwt-cpp
    gRPC::grpc++
    nlohmann_json::nlohmann_json
    protobuf::libprotobuf
    silkworm_core
    silkworm_node)

add_library(silkrpc ${SILKRPC_SRC} ${SILKWORM_INTERFACE_SRC})

add_dependencies(silkrpc generate_ethbackend_grpc generate_kv_grpc generate_mining_grpc generate_txpool_grpc)
target_include_directories(silkrpc PUBLIC
        ${SILKWORM_MAIN_DIR}
        ${SILKWORM_MAIN_SRC_DIR}/interfaces
        ${SILKWORM_MAIN_DIR}/third_party/cbor-cpp
        ${SILKWORM_MAIN_DIR}/third_party/glaze/include
        ${SILKWORM_MAIN_DIR}/third_party/evmone/lib)
target_link_libraries(silkrpc PUBLIC ${SILKRPC_LIBRARIES})
