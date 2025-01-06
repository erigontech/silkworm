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
