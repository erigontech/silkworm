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

# Tests
add_subdirectory(test)

if(NOT SILKWORM_CORE_ONLY)
  # Benchmarks
  add_subdirectory(benchmark)

  find_package(absl REQUIRED)
  find_package(Boost REQUIRED)
  find_package(CLI11 REQUIRED)

  add_subdirectory(common)
  add_subdirectory(dev)

  # Silkworm components
  add_subdirectory(rpcdaemon)

  set(SILKWORM_CMD_SRC
      silkworm.cpp
      common/db_checklist.cpp
      common/db_checklist.hpp
      common/db_max_readers_option.cpp
      common/db_max_readers_option.hpp
      common/human_size_parser_validator.hpp
      common/snapshot_options.cpp
      common/snapshot_options.hpp
  )

  add_executable(silkworm "${SILKWORM_CMD_SRC}")
  target_link_libraries(silkworm PRIVATE silkworm_node silkworm_sync cmd_common $<$<BOOL:${MSVC}>:Kernel32.lib>)

  add_executable(sentry sentry.cpp)
  target_link_libraries(sentry PRIVATE silkworm_sentry cmd_common)

endif()
