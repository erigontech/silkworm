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
find_package(Boost REQUIRED COMPONENTS headers container thread)
find_package(CPPTRACE REQUIRED)
find_package(Catch2 REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
find_package(magic_enum REQUIRED)
find_package(spdlog REQUIRED)

set(LIBS_PUBLIC
    silkworm_core
    silkworm_interfaces
    absl::log
    absl::strings
    asio-grpc::asio-grpc
    Boost::headers
    Boost::thread
    CPPTRACE::CPPTRACE
    gRPC::grpc++
)

# cmake-format: off
set(LIBS_PRIVATE
    absl::time
    Boost::container # required for asio-grpc
    magic_enum::magic_enum
    spdlog::spdlog
    silkworm-buildinfo
)
# cmake-format: on

silkworm_library(
  silkworm_infra
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

# silkworm_infra_cli depends on silkworm_infra
add_subdirectory(cli)

# silkworm_infra_test_util depends on silkworm_infra
add_subdirectory(test_util)

# unit tests
target_link_libraries(silkworm_infra_test PRIVATE GTest::gmock silkworm_infra_test_util)
