# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(absl REQUIRED)
find_package(Boost REQUIRED COMPONENTS headers)
find_package(CLI11 REQUIRED)
find_package(gRPC REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Protobuf REQUIRED)
find_package(tomlplusplus REQUIRED)

add_executable(backend_kv_server "${SILKWORM_MAIN_DIR}/silkworm/node/cli/backend_kv_server.cpp")
target_link_libraries(backend_kv_server PRIVATE silkworm_db_cli silkworm_node silkworm_sync)

add_executable(check_blockhashes "${SILKWORM_MAIN_DIR}/silkworm/db/cli/check_blockhashes.cpp")
target_link_libraries(check_blockhashes PRIVATE silkworm_db CLI11::CLI11)

add_executable(check_changes "${SILKWORM_MAIN_DIR}/silkworm/db/cli/check_changes.cpp")
target_link_libraries(check_changes PRIVATE silkworm_db CLI11::CLI11 absl::time)

add_executable(check_hashstate "${SILKWORM_MAIN_DIR}/silkworm/db/cli/check_hashstate.cpp")
target_link_libraries(check_hashstate PRIVATE silkworm_db CLI11::CLI11)

add_executable(check_log_indices "${SILKWORM_MAIN_DIR}/silkworm/db/cli/check_log_indices.cpp")
target_link_libraries(check_log_indices PRIVATE silkworm_infra_cli silkworm_db cborcpp CLI11::CLI11)

add_executable(check_senders "${SILKWORM_MAIN_DIR}/silkworm/db/cli/check_senders.cpp")
target_link_libraries(check_senders PRIVATE silkworm_infra_cli silkworm_db)

add_executable(check_tx_lookup "${SILKWORM_MAIN_DIR}/silkworm/db/cli/check_tx_lookup.cpp")
target_link_libraries(check_tx_lookup PRIVATE silkworm_db CLI11::CLI11)

add_executable(embed_toml "${SILKWORM_MAIN_DIR}/silkworm/dev/cli/embed_toml.cpp")
target_link_libraries(embed_toml PRIVATE absl::strings CLI11::CLI11 tomlplusplus::tomlplusplus silkworm_dev)

add_executable(embed_json "${SILKWORM_MAIN_DIR}/silkworm/dev/cli/embed_json.cpp")
target_link_libraries(embed_json PRIVATE CLI11::CLI11 Boost::headers silkworm_dev)

add_executable(grpc_toolbox "${SILKWORM_MAIN_DIR}/silkworm/rpc/cli/grpc_toolbox.cpp")
target_include_directories(grpc_toolbox PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(grpc_toolbox absl::flags_parse gRPC::grpc++ protobuf::libprotobuf silkworm_rpcdaemon)

add_executable(kzg_g2_uncompress "${SILKWORM_MAIN_DIR}/silkworm/dev/cli/kzg_g2_uncompress.cpp")
target_link_libraries(kzg_g2_uncompress silkworm_dev blst::blst)

add_executable(scan_txs "${SILKWORM_MAIN_DIR}/silkworm/db/cli/scan_txs.cpp")
target_link_libraries(scan_txs PRIVATE silkworm_db CLI11::CLI11 absl::time)

add_executable(snapshots "${SILKWORM_MAIN_DIR}/silkworm/db/cli/snapshots.cpp")
target_link_libraries(snapshots PRIVATE absl::strings silkworm_infra_cli magic_enum::magic_enum silkworm_db)

add_executable(db_toolbox "${SILKWORM_MAIN_DIR}/silkworm/db/cli/db_toolbox.cpp")
target_link_libraries(db_toolbox PRIVATE silkworm_db silkworm_infra_cli CLI11::CLI11 magic_enum::magic_enum)

add_executable(staged_pipeline "${SILKWORM_MAIN_DIR}/silkworm/node/cli/staged_pipeline.cpp")
target_link_libraries(staged_pipeline PRIVATE silkworm_node silkworm_infra_cli CLI11::CLI11 magic_enum::magic_enum)

if(MSVC)
    add_link_options(/STACK:${SILKWORM_STACK_SIZE})
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_link_options(-Wl,-stack_size -Wl,${SILKWORM_STACK_SIZE})
else()
    add_link_options(-Wl,-z,stack-size=${SILKWORM_STACK_SIZE})
endif()

add_executable(state_transition "${SILKWORM_MAIN_DIR}/silkworm/dev/cli/runner.cpp")
target_link_libraries(state_transition PRIVATE silkworm_dev)
set(SILKWORM_DEV_CLI "${SILKWORM_MAIN_DIR}/silkworm/dev/cli")
configure_file("${SILKWORM_DEV_CLI}/state_transition_sample1.json" ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample1.json COPYONLY)
configure_file("${SILKWORM_DEV_CLI}/state_transition_sample2.json" ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample2.json COPYONLY)
configure_file("${SILKWORM_DEV_CLI}/state_transition_sample3.json" ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample3.json COPYONLY)
configure_file("${SILKWORM_DEV_CLI}/state_transition_sample4.json" ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample4.json COPYONLY)
