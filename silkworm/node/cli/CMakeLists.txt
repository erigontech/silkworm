# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(CLI11 REQUIRED)
find_package(magic_enum REQUIRED)

add_library(silkworm_node_cli "node_options.cpp")
target_link_libraries(silkworm_node_cli PUBLIC silkworm_node CLI11::CLI11)

add_executable(backend_kv_server "backend_kv_server.cpp")
target_link_libraries(backend_kv_server PRIVATE silkworm_node silkworm_infra_cli silkworm_db_cli silkworm_sync)

add_executable(staged_pipeline "staged_pipeline.cpp")
target_link_libraries(staged_pipeline PRIVATE silkworm_node silkworm_infra_cli magic_enum::magic_enum)
