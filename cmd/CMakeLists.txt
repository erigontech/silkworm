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
  add_link_options(/STACK:${SILKWORM_STACK_SIZE})
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,${SILKWORM_STACK_SIZE})
else()
  add_link_options(-Wl,-z,stack-size=${SILKWORM_STACK_SIZE})
endif()

hunter_add_package(nlohmann_json)
find_package(nlohmann_json CONFIG REQUIRED)

# Tests
add_subdirectory(test)

if(NOT SILKWORM_CORE_ONLY)
  # Benchmarks
  add_subdirectory(benchmark)

  find_package(absl REQUIRED)
  find_package(Boost REQUIRED)
  find_package(CLI11 REQUIRED)

  set(COMMON_SRC
      common/common.cpp
      common/common.hpp
      common/ip_endpoint_option.cpp
      common/ip_endpoint_option.hpp
      common/shutdown_signal.cpp
      common/shutdown_signal.hpp
  )
  add_library(cmd_common "${COMMON_SRC}")
  target_link_libraries(cmd_common silkworm-buildinfo CLI11::CLI11 silkworm_infra)

  add_subdirectory(dev)

  # Silkworm components
  add_subdirectory(rpcdaemon)
#  add_subdirectory(state)
#  add_subdirectory(statetransition)

  set(SILKWORM_CMD_SRC
      silkworm.cpp
      common/human_size_parser_validator.hpp
      common/settings.hpp
      common/sentry_options.cpp
      common/sentry_options.hpp
      common/snapshot_options.cpp
      common/snapshot_options.hpp
  )

  add_executable(silkworm "${SILKWORM_CMD_SRC}")
  target_link_libraries(silkworm PRIVATE silkworm_node silkworm_sync cmd_common $<$<BOOL:${MSVC}>:Kernel32.lib>)

  add_executable(check_changes check_changes.cpp)
  target_link_libraries(check_changes PRIVATE silkworm_node CLI11::CLI11 absl::time)

  add_executable(scan_txs scan_txs.cpp)
  target_link_libraries(scan_txs PRIVATE silkworm_node CLI11::CLI11 absl::time)

  add_executable(state_transition state_transition.cpp expected_state.cpp )
  target_link_libraries(state_transition PRIVATE silkworm_node CLI11::CLI11 absl::time nlohmann_json::nlohmann_json)

  add_executable(check_pow check_pow.cpp)
  target_link_libraries(check_pow PRIVATE silkworm_node CLI11::CLI11)

  add_executable(toolbox toolbox.cpp)
  target_link_libraries(toolbox PRIVATE silkworm_node CLI11::CLI11)

  add_executable(genesistool genesistool.cpp)
  target_link_libraries(genesistool PRIVATE CLI11::CLI11 Boost::headers)

  add_executable(check_hashstate check_hashstate.cpp)
  target_link_libraries(check_hashstate PRIVATE silkworm_node CLI11::CLI11)

  add_executable(check_tx_lookup check_tx_lookup.cpp)
  target_link_libraries(check_tx_lookup PRIVATE silkworm_node CLI11::CLI11)

  add_executable(check_blockhashes check_blockhashes.cpp)
  target_link_libraries(check_blockhashes PRIVATE silkworm_node CLI11::CLI11)

  add_executable(check_senders check_senders.cpp)
  target_link_libraries(check_senders PRIVATE silkworm_node cmd_common)

  add_executable(snapshots snapshots.cpp)
  target_link_libraries(snapshots PRIVATE silkworm_node cmd_common torrent-rasterbar)

  add_executable(sentry sentry.cpp common/sentry_options.cpp common/sentry_options.hpp)
  target_link_libraries(sentry PRIVATE silkworm_sentry cmd_common)

  # cmake-format: off
  set(BACKEND_KV_SERVER_SRC
      backend_kv_server.cpp
      common/db_max_readers_option.cpp
      common/db_max_readers_option.hpp
      common/settings.hpp
  )
  # cmake-format: on

  add_executable(backend_kv_server "${BACKEND_KV_SERVER_SRC}")
  target_link_libraries(backend_kv_server PRIVATE silkworm_node silkworm_sync cmd_common)

endif()
