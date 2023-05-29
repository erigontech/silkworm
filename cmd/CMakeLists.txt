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
  # Benchmarks
  add_subdirectory(benchmark)

  find_package(absl REQUIRED)
  find_package(Boost REQUIRED)
  find_package(CLI11 REQUIRED)

  if(SILKWORM_USE_MIMALLOC AND CONAN_PACKAGE_MANAGER)
    find_package(mimalloc REQUIRED)
  endif()

  # Common modules for commands
  add_subdirectory(common)

  # Development utility tools
  add_subdirectory(dev)

  # Silkworm components
  set(SILKWORM_CMD_SRC
      silkworm.cpp
      common/db_checklist.cpp
      common/db_checklist.hpp
      common/db_max_readers_option.cpp
      common/db_max_readers_option.hpp
      common/human_size_parser_validator.hpp
      common/sentry_options.cpp
      common/sentry_options.hpp
      common/snapshot_options.cpp
      common/snapshot_options.hpp
  )
  add_executable(silkworm "${SILKWORM_CMD_SRC}")
  target_link_libraries(silkworm PRIVATE silkworm_node silkworm_sync cmd_common $<$<BOOL:${MSVC}>:Kernel32.lib>)

  # SilkRpc Daemon
  # cmake-format: off
  set(SILKRPC_DAEMON_LIBRARIES
      silkrpc
      absl::flags_parse
      cmd_common
  )
  # cmake-format: on
  if(SILKWORM_USE_MIMALLOC)
    if(CONAN_PACKAGE_MANAGER)
      list(APPEND SILKRPC_DAEMON_LIBRARIES mimalloc::mimalloc)
    else()
      list(APPEND SILKRPC_DAEMON_LIBRARIES mimalloc)
    endif()
  endif()

  add_executable(silkrpcdaemon rpcdaemon.cpp)
  target_include_directories(silkrpcdaemon PUBLIC ${CMAKE_SOURCE_DIR})
  target_link_libraries(silkrpcdaemon PRIVATE ${SILKRPC_DAEMON_LIBRARIES})

  # cmake-format: off
  set(SENTRY_CMD_SRC
      sentry.cpp
      common/sentry_options.cpp
      common/sentry_options.hpp
  )
  # cmake-format: on
  add_executable(sentry "${SENTRY_CMD_SRC}")
  target_link_libraries(sentry PRIVATE silkworm_sentry cmd_common)

endif()
