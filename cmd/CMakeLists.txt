#[[
   Copyright 2020-2022 The Silkworm Authors

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

# each command links with these libraries
set(COMMON_LIBS
  CLI11::CLI11
  silkworm_node
)

# Adds a command build target
# Usage:
# cmd(my_tool)
# - produces a my_tool binary from my_tool.cpp and links with COMMON_LIBS
# cmd(my_tool SRC file1.cpp file2.cpp)
# - to add extra sources
# cmd(my_tool LIBS lib1 lib2)
# - to add extra libs
function(cmd name)
  cmake_parse_arguments(PARSE_ARGV 1 ARG "" "" "SRC;LIBS")

  list(APPEND ARG_SRC ${name}.cpp)
  add_executable(${name} ${ARG_SRC})

  list(PREPEND ARG_LIBS ${COMMON_LIBS})
  target_link_libraries(${name} PRIVATE ${ARG_LIBS})
endfunction()

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

  find_package(absl CONFIG REQUIRED)
  find_package(CLI11 CONFIG REQUIRED)

  # silkworm binary
  set(silkworm_libs silkworm-buildinfo)
  if(MSVC)
    list(APPEND silkworm_libs Kernel32.lib)
  endif()
  cmd(silkworm SRC common.cpp LIBS ${silkworm_libs})

  # commands
  cmd(backend_kv_server LIBS silkworm-buildinfo)
  cmd(check_blockhashes)
  cmd(check_changes LIBS absl::time)
  cmd(check_hashstate)
  cmd(check_pow)
  cmd(check_tx_lookup)
  cmd(downloader SRC common.cpp LIBS silkworm-buildinfo)
  cmd(genesistool)
  cmd(history_index)
  cmd(log_index LIBS cborcpp)
  cmd(scan_txs LIBS absl::time)
  cmd(toolbox)
  cmd(trie)
  cmd(tx_lookup)
  cmd(unwind_history_index)
  cmd(unwind_log_index)
  cmd(unwind_tx_lookup)

endif()
