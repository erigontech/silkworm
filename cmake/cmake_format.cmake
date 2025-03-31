# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_program(CMAKE_FORMAT cmake-format)
if(NOT EXISTS "${CMAKE_FORMAT}")
  message(FATAL_ERROR "'cmake-format' command not found in PATH. Please install it using:\n\t"
                      "pip3 install --user cmake-format==0.6.13"
  )
endif()

cmake_policy(SET CMP0009 NEW)
file(
  GLOB_RECURSE SRC
  LIST_DIRECTORIES false
  "cmake/*.cmake"
  "cmake/CMakeLists.txt"
  "cmd/*.cmake"
  "cmd/CMakeLists.txt"
  "examples/*.cmake"
  "examples/CMakeLists.txt"
  "silkworm/*.cmake"
  "silkworm/CMakeLists.txt"
  "third_party/CMakeLists.txt"
)
list(PREPEND SRC "${CMAKE_CURRENT_LIST_DIR}/../CMakeLists.txt")
list(FILTER SRC EXCLUDE REGEX "third_party/.+/(.+/)+CMakeLists.txt$")

execute_process(
  COMMAND "${CMAKE_FORMAT}" --in-place "--config-file=${CMAKE_CURRENT_LIST_DIR}/cmake_format.yaml" ${SRC}
  COMMAND_ERROR_IS_FATAL ANY
)
