#[[
   Copyright 2022 The Silkworm Authors

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

if(MSVC)
  add_link_options(/STACK:0x1000000)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,0x1000000)
else()
  add_link_options(-Wl,-z,stack-size=0x1000000)
endif()

# Tests
add_subdirectory(test)

if(NOT SILKWORM_CORE_ONLY)
  # Benchmarks
  add_subdirectory(benchmark)

  find_package(absl CONFIG REQUIRED)
  find_package(CLI11 CONFIG REQUIRED)

  add_executable(silkworm silkworm.cpp common.cpp)
  target_link_libraries(silkworm PRIVATE silkworm_node silkworm-buildinfo CLI11::CLI11 $<$<BOOL:${MSVC}>:Kernel32.lib>)

  add_executable(check_changes check_changes.cpp)
  target_link_libraries(check_changes PRIVATE silkworm_node CLI11::CLI11 absl::time)

  add_executable(scan_txs scan_txs.cpp)
  target_link_libraries(scan_txs PRIVATE silkworm_node CLI11::CLI11 absl::time)

  add_executable(check_pow check_pow.cpp)
  target_link_libraries(check_pow PRIVATE silkworm_node CLI11::CLI11)

  add_executable(toolbox toolbox.cpp)
  target_link_libraries(toolbox PRIVATE silkworm_node CLI11::CLI11)

  add_executable(genesistool genesistool.cpp)
  target_link_libraries(genesistool PRIVATE CLI11::CLI11)

  add_executable(check_hashstate check_hashstate.cpp)
  target_link_libraries(check_hashstate PRIVATE silkworm_node CLI11::CLI11)

  add_executable(check_tx_lookup check_tx_lookup.cpp)
  target_link_libraries(check_tx_lookup PRIVATE silkworm_node CLI11::CLI11)

  add_executable(check_blockhashes check_blockhashes.cpp)
  target_link_libraries(check_blockhashes PRIVATE silkworm_node CLI11::CLI11)

  add_executable(check_senders check_senders.cpp common.cpp)
  target_link_libraries(check_senders PRIVATE silkworm_node silkworm-buildinfo CLI11::CLI11)

  add_executable(snapshots snapshots.cpp common.cpp)
  target_link_libraries(snapshots PRIVATE silkworm_node silkworm-buildinfo CLI11::CLI11 torrent-rasterbar)

  add_executable(downloader downloader.cpp common.cpp)
  target_link_libraries(downloader PRIVATE silkworm_node silkworm-buildinfo CLI11::CLI11)

  add_executable(sentry sentry.cpp common.cpp)
  target_link_libraries(sentry PRIVATE silkworm_node silkworm-buildinfo CLI11::CLI11 silkworm_sentry)

  add_executable(backend_kv_server backend_kv_server.cpp common.cpp)
  target_link_libraries(backend_kv_server PRIVATE silkworm_node silkworm-buildinfo CLI11::CLI11)

endif()
