#[[
   Copyright 2024 The Silkworm Authors

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

find_package(asio-grpc REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
find_package(nlohmann_json REQUIRED)

# cmake-format: off
set(LIBS_PRIVATE
    gRPC::grpc++
    silkworm_interfaces
)
# cmake-format: on

# cmake-format: off
set(LIBS_PUBLIC
    asio-grpc::asio-grpc
    nlohmann_json::nlohmann_json
    silkworm_core
    silkworm_infra
    silkworm_db
)
# cmake-format: on

silkworm_library(
  silkworm_execution
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

target_link_libraries(silkworm_execution_test PRIVATE GTest::gmock silkworm_infra_test_util silkworm_db_test_util)
