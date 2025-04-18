# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# Tests
add_subdirectory(test)

if(NOT SILKWORM_CORE_ONLY)
  # Benchmarks
  add_subdirectory(benchmark)

  if(SILKWORM_USE_MIMALLOC)
    find_package(mimalloc REQUIRED)
  endif()

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
