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
find_package(gRPC REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)

# Silkrpc library
file(
  GLOB_RECURSE
  SILKRPC_SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.cc"
  "*.hpp"
  "*.c"
  "*.h"
)
list(FILTER SILKRPC_SRC EXCLUDE REGEX "main\\.cpp$|_test\\.cpp$|\\.pb\\.cc|\\.pb\\.h")

set(SILKRPC_LIBRARIES
    silkworm_node
    silkworm_core
    silkworm_interfaces
    asio-grpc::asio-grpc
    gRPC::grpc++
    jwt-cpp::jwt-cpp
    nlohmann_json::nlohmann_json
    absl::flat_hash_map
    absl::flat_hash_set
    absl::btree
    Boost::container
    Boost::thread
    protobuf::libprotobuf
    intx::intx
)

add_library(silkrpc "${SILKRPC_SRC}")

# Suppress ASAN/TSAN in gRPC to avoid ODR violation when building Silkworm with sanitizers See
# https://github.com/grpc/grpc/issues/19224
if(SILKWORM_SANITIZE)
  target_compile_definitions(silkrpc PRIVATE GRPC_ASAN_SUPPRESSED GRPC_TSAN_SUPPRESSED)
endif()

# cmake-format: off
target_include_directories(
  silkrpc
  PUBLIC "${SILKWORM_MAIN_DIR}"
         "${SILKWORM_MAIN_DIR}/third_party/cbor-cpp"
         "${SILKWORM_MAIN_DIR}/third_party/glaze/include"
         "${SILKWORM_MAIN_DIR}/third_party/evmone/lib"
)
# cmake-format: on

target_link_libraries(silkrpc PUBLIC ${SILKRPC_LIBRARIES})
