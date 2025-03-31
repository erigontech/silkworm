# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

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
