# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED COMPONENTS btree)
# circular_buffer
find_package(Boost REQUIRED COMPONENTS headers)
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)

set(LIBS_PUBLIC
    Boost::headers
    ethash::keccak
    evmc
    secp256k1
    silkworm_core
    silkworm_db
    silkworm_datastore_etl
    silkworm_infra
)

# cmake-format: off
set(LIBS_PRIVATE
    absl::btree
    magic_enum::magic_enum
    Microsoft.GSL::GSL
    silkworm_execution
)
# cmake-format: on

silkworm_library(
  silkworm_stages
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

target_link_libraries(silkworm_stages_test PRIVATE silkworm_db_test_util)
