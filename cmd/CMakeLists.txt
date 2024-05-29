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

# Tests
add_subdirectory(test)

if(NOT SILKWORM_CORE_ONLY)
  # C API
  add_subdirectory(capi)

  # Benchmarks
  add_subdirectory(benchmark)

  find_package(absl REQUIRED)
  find_package(CLI11 REQUIRED)

  if(SILKWORM_USE_MIMALLOC)
    find_package(mimalloc REQUIRED)
  endif()

  # Common modules for commands
  add_subdirectory(common)

  # State transition and fuzzy tests runner tool
  add_subdirectory(state-transition)

  # Development utility tools
  add_subdirectory(dev)

  # Silkworm runnable components

  # [=] "all-in-one" Silkworm component
  set(SILKWORM_CMD_SRC
      silkworm.cpp
      common/db_checklist.cpp
      common/db_checklist.hpp
      common/db_max_readers_option.cpp
      common/db_max_readers_option.hpp
      common/node_options.cpp
      common/node_options.hpp
      common/rpcdaemon_options.cpp
      common/rpcdaemon_options.hpp
      common/sentry_options.cpp
      common/sentry_options.hpp
      common/snapshot_options.cpp
      common/snapshot_options.hpp
  )
  set(SILKWORM_LIBRARIES silkworm_node silkworm_sync cmd_common $<$<BOOL:${MSVC}>:Kernel32.lib>)
  add_executable(silkworm "${SILKWORM_CMD_SRC}")
  target_link_libraries(silkworm PRIVATE ${SILKWORM_LIBRARIES})

  # [=] standalone RpcDaemon component
  set(RPCDAEMON_CMD_SRC rpcdaemon.cpp common/rpcdaemon_options.cpp common/rpcdaemon_options.hpp)
  set(RPCDAEMON_LIBRARIES silkworm_rpcdaemon absl::flags_parse cmd_common)
  if(SILKWORM_USE_MIMALLOC)
    list(APPEND RPCDAEMON_LIBRARIES mimalloc::mimalloc)
  endif()

  add_executable(rpcdaemon "${RPCDAEMON_CMD_SRC}")
  target_include_directories(rpcdaemon PUBLIC ${CMAKE_SOURCE_DIR})
  target_link_libraries(rpcdaemon PRIVATE ${RPCDAEMON_LIBRARIES})

  # [=] standalone Sentry component
  set(SENTRY_CMD_SRC sentry.cpp common/sentry_options.cpp common/sentry_options.hpp)
  add_executable(sentry "${SENTRY_CMD_SRC}")
  target_link_libraries(sentry PRIVATE silkworm_sentry cmd_common)

endif()
