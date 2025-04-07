# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

add_subdirectory(datastore)

find_package(absl REQUIRED)
find_package(asio-grpc REQUIRED)
find_package(Boost REQUIRED COMPONENTS headers)
find_package(gRPC REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(nlohmann_json REQUIRED)
find_package(Protobuf REQUIRED)

set(LIBS_PUBLIC
    absl::btree
    absl::flat_hash_map
    absl::flat_hash_set
    absl::strings
    silkworm_core
    silkworm_infra
    silkworm_datastore
)

set(LIBS_PRIVATE
    cborcpp
    magic_enum::magic_enum
    Microsoft.GSL::GSL
    nlohmann_json::nlohmann_json
    asio-grpc::asio-grpc
    Boost::headers
    gRPC::grpc++
    protobuf::libprotobuf
    silkworm_datastore_etl
)

silkworm_library(
  silkworm_db
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

# silkworm_db_cli depends on silkworm_db
add_subdirectory(cli)

# silkworm_db_test_util depends on silkworm_db
add_subdirectory(test_util)

target_link_libraries(silkworm_db_test PRIVATE silkworm_db_test_util silkworm_infra_test_util)
