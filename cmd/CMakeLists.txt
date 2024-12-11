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

  if(SILKWORM_USE_MIMALLOC)
    find_package(mimalloc REQUIRED)
  endif()

  # State transition and fuzzy tests runner tool
  add_subdirectory(state-transition)

  # Development utility tools
  add_subdirectory(dev)

  # Silkworm runnable components

  # [=] "all-in-one" Silkworm component
  # cmake-format: off
  set(SILKWORM_LIBRARIES
      silkworm_node
      silkworm_db_cli
      silkworm_node_cli
      silkworm_rpcdaemon_cli
      silkworm_sentry_cli
      $<$<BOOL:${MSVC}>:Kernel32.lib>
  )
  # cmake-format: on
  add_executable(silkworm silkworm.cpp)
  target_link_libraries(silkworm PRIVATE ${SILKWORM_LIBRARIES})

  # [=] standalone RpcDaemon component
  set(RPCDAEMON_LIBRARIES silkworm_rpcdaemon silkworm_rpcdaemon_cli)
  if(SILKWORM_USE_MIMALLOC)
    list(APPEND RPCDAEMON_LIBRARIES mimalloc-static)
  endif()

  add_executable(rpcdaemon rpcdaemon.cpp)
  target_include_directories(rpcdaemon PUBLIC ${CMAKE_SOURCE_DIR})
  target_link_libraries(rpcdaemon PRIVATE ${RPCDAEMON_LIBRARIES})

  # [=] standalone Sentry component
  add_executable(sentry sentry.cpp)
  target_link_libraries(sentry PRIVATE silkworm_sentry silkworm_sentry_cli)

endif()
