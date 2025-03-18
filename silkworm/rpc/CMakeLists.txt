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

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED)
find_package(asio-grpc REQUIRED)
find_package(Boost REQUIRED COMPONENTS headers container)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
find_package(jwt-cpp REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(roaring REQUIRED)

set(SILKWORM_RPCDAEMON_PUBLIC_LIBRARIES
    silkworm_db
    silkworm_core
    silkworm_interfaces
    asio-grpc::asio-grpc
    cborcpp
    evmone
    libdeflate
    glaze::glaze
    gRPC::grpc++
    jwt-cpp::jwt-cpp
    nlohmann_json::nlohmann_json
    absl::btree
    Boost::container
    Boost::headers
    protobuf::libprotobuf
    intx::intx
)

# cmake-format: off
set(SILKWORM_RPCDAEMON_PRIVATE_LIBRARIES
    absl::strings
    evmc::instructions
    roaring::roaring
    silkworm_execution
)
# cmake-format: on

silkworm_library(
  silkworm_rpcdaemon
  PUBLIC ${SILKWORM_RPCDAEMON_PUBLIC_LIBRARIES}
  PRIVATE ${SILKWORM_RPCDAEMON_PRIVATE_LIBRARIES}
)

# silkworm_rpcdaemon_cli depends on silkworm_rpcdaemon
add_subdirectory(cli)

# silkworm_rpcdaemon_test_util depends on silkworm_rpcdaemon
add_subdirectory(test_util)

target_link_libraries(
  silkworm_rpcdaemon_test PRIVATE silkworm_infra_test_util silkworm_rpcdaemon_test_util GTest::gmock
)
