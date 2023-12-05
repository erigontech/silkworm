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

find_package(absl REQUIRED)
find_package(Boost REQUIRED headers)
find_package(CLI11 REQUIRED)
find_package(gRPC REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Protobuf REQUIRED)
find_package(tomlplusplus REQUIRED)

# cmake-format: off
set(BACKEND_KV_SERVER_SRC
        backend_kv_server.cpp
        ../common/db_max_readers_option.cpp
        ../common/db_max_readers_option.hpp
        )
# cmake-format: on

add_executable(backend_kv_server "${BACKEND_KV_SERVER_SRC}")
target_link_libraries(backend_kv_server PRIVATE silkworm_node silkworm_sync cmd_common)

add_executable(check_blockhashes check_blockhashes.cpp)
target_link_libraries(check_blockhashes PRIVATE silkworm_node CLI11::CLI11)

add_executable(check_changes check_changes.cpp)
target_link_libraries(check_changes PRIVATE silkworm_node CLI11::CLI11 absl::time)

add_executable(check_hashstate check_hashstate.cpp)
target_link_libraries(check_hashstate PRIVATE silkworm_node CLI11::CLI11)

add_executable(check_log_indices check_log_indices.cpp)
target_link_libraries(check_log_indices PRIVATE silkworm_node cborcpp cmd_common CLI11::CLI11)

add_executable(check_pow check_pow.cpp)
target_link_libraries(check_pow PRIVATE silkworm_node CLI11::CLI11)

add_executable(check_senders check_senders.cpp)
target_link_libraries(check_senders PRIVATE silkworm_node cmd_common)

add_executable(check_tx_lookup check_tx_lookup.cpp)
target_link_libraries(check_tx_lookup PRIVATE silkworm_node CLI11::CLI11)

add_executable(embed_toml embed_toml.cpp)
target_link_libraries(embed_toml PRIVATE CLI11::CLI11 tomlplusplus::tomlplusplus)

add_executable(genesistool genesistool.cpp)
target_link_libraries(genesistool PRIVATE CLI11::CLI11 Boost::headers)

add_executable(grpc_toolbox grpc_toolbox.cpp)
target_include_directories(grpc_toolbox PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(grpc_toolbox absl::flags_parse gRPC::grpc++ protobuf::libprotobuf silkworm_rpcdaemon)

add_executable(kzg_g2_uncompress kzg_g2_uncompress.cpp)
target_link_libraries(kzg_g2_uncompress silkworm_core blst)

add_executable(scan_txs scan_txs.cpp)
target_link_libraries(scan_txs PRIVATE silkworm_node CLI11::CLI11 absl::time)

add_executable(snapshots snapshots.cpp)
target_link_libraries(snapshots PRIVATE silkworm_node cmd_common torrent-rasterbar magic_enum::magic_enum)

add_executable(db_toolbox db_toolbox.cpp)
target_link_libraries(db_toolbox PRIVATE silkworm_node CLI11::CLI11 magic_enum::magic_enum)
