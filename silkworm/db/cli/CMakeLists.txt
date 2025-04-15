# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(absl REQUIRED)
find_package(Boost REQUIRED COMPONENTS headers)
find_package(CLI11 REQUIRED)
find_package(magic_enum REQUIRED)

add_library(silkworm_db_cli "db_max_readers_option.cpp" "snapshot_options.cpp")
target_link_libraries(
  silkworm_db_cli
  PUBLIC CLI11::CLI11 silkworm_snapshots
  PRIVATE silkworm_datastore_kvdb
)

add_executable(check_blockhashes "check_blockhashes.cpp")
target_link_libraries(check_blockhashes PRIVATE silkworm_db CLI11::CLI11)

add_executable(check_changes "check_changes.cpp")
target_link_libraries(check_changes PRIVATE silkworm_db CLI11::CLI11 absl::time)

add_executable(check_hashstate "check_hashstate.cpp")
target_link_libraries(check_hashstate PRIVATE silkworm_db CLI11::CLI11)

add_executable(check_log_indices "check_log_indices.cpp")
target_link_libraries(check_log_indices PRIVATE silkworm_db silkworm_infra_cli cborcpp)

add_executable(check_senders "check_senders.cpp")
target_link_libraries(check_senders PRIVATE silkworm_db silkworm_infra_cli)

add_executable(check_tx_lookup "check_tx_lookup.cpp")
target_link_libraries(check_tx_lookup PRIVATE silkworm_db CLI11::CLI11)

add_executable(scan_txs "scan_txs.cpp")
target_link_libraries(scan_txs PRIVATE silkworm_db CLI11::CLI11 absl::time)

add_executable(snapshots "snapshots.cpp")
target_link_libraries(snapshots PRIVATE silkworm_db silkworm_infra_cli absl::strings magic_enum::magic_enum)

add_executable(db_toolbox "db_toolbox.cpp")
target_link_libraries(db_toolbox PRIVATE silkworm_db silkworm_infra_cli magic_enum::magic_enum)
