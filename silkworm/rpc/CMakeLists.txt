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
find_package(Boost REQUIRED headers container)
find_package(gRPC REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(roaring REQUIRED)

# Silkrpc library
file(
  GLOB_RECURSE
  SILKWORM_RPCDAEMON_SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.cc"
  "*.hpp"
  "*.c"
  "*.h"
)
list(FILTER SILKWORM_RPCDAEMON_SRC EXCLUDE REGEX "main\\.cpp$|_test\\.cpp$|\\.pb\\.cc|\\.pb\\.h")

set(SILKWORM_RPCDAEMON_PUBLIC_LIBRARIES
    silkworm_node
    silkworm_core
    silkworm_interfaces
    asio-grpc::asio-grpc
    cborcpp
    evmone
    glaze::glaze
    gRPC::grpc++
    jwt-cpp::jwt-cpp
    nlohmann_json::nlohmann_json
    absl::flat_hash_map
    absl::flat_hash_set
    absl::btree
    Boost::container
    Boost::headers
    protobuf::libprotobuf
    intx::intx
    pico_http_parser
)

set(SILKWORM_RPCDAEMON_PRIVATE_LIBRARIES evmc::instructions roaring::roaring)

add_library(silkworm_rpcdaemon "${SILKWORM_RPCDAEMON_SRC}")

target_link_libraries(
  silkworm_rpcdaemon
  PUBLIC ${SILKWORM_RPCDAEMON_PUBLIC_LIBRARIES}
  PRIVATE ${SILKWORM_RPCDAEMON_PRIVATE_LIBRARIES}
)
