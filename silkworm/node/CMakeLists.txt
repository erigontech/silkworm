# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

add_subdirectory(stagedsync/stages)

find_package(absl REQUIRED COMPONENTS strings)
find_package(asio-grpc REQUIRED)
find_package(Boost REQUIRED COMPONENTS headers)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(Protobuf REQUIRED)

set(SILKWORM_NODE_PUBLIC_LIBS
    silkworm_core
    silkworm_db
    silkworm_infra
    silkworm_sentry
    silkworm_snapshots
    asio-grpc::asio-grpc
    Boost::headers
    gRPC::grpc++
    protobuf::libprotobuf
)

set(SILKWORM_NODE_PRIVATE_LIBS
    absl::strings
    evmone
    magic_enum::magic_enum
    Microsoft.GSL::GSL
    silkworm_datastore_etl
    silkworm_execution
    silkworm_interfaces
    silkworm_stages
    silkworm_sync
)

silkworm_library(
  silkworm_node
  PUBLIC ${SILKWORM_NODE_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_NODE_PRIVATE_LIBS}
)

# silkworm_node_cli depends on silkworm_node
add_subdirectory(cli)

# silkworm_node_test_util depends on silkworm_node
add_subdirectory(test_util)

target_link_libraries(silkworm_node_test PRIVATE silkworm_node_test_util GTest::gmock)
