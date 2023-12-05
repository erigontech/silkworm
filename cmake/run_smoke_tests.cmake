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

if(NOT SILKWORM_BUILD_DIR)
  set(SILKWORM_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../build")
endif()
file(REAL_PATH "${SILKWORM_BUILD_DIR}" SILKWORM_BUILD_DIR)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_EXECUTABLE_SUFFIX ".exe")
endif()

file(
  GLOB_RECURSE COMMANDS
  LIST_DIRECTORIES false
  "${SILKWORM_BUILD_DIR}/*_test${CMAKE_EXECUTABLE_SUFFIX}"
  "${SILKWORM_BUILD_DIR}/*execute${CMAKE_EXECUTABLE_SUFFIX}"
  "${SILKWORM_BUILD_DIR}/*db_toolbox${CMAKE_EXECUTABLE_SUFFIX}"
  "${SILKWORM_BUILD_DIR}/*rpcdaemon${CMAKE_EXECUTABLE_SUFFIX}"
  "${SILKWORM_BUILD_DIR}/*sentry${CMAKE_EXECUTABLE_SUFFIX}"
  "${SILKWORM_BUILD_DIR}/*silkworm${CMAKE_EXECUTABLE_SUFFIX}"
)
list(FILTER COMMANDS EXCLUDE REGEX "sentry_client_test${CMAKE_EXECUTABLE_SUFFIX}\$")

foreach(COMMAND IN LISTS COMMANDS)
  file(RELATIVE_PATH COMMAND_REL_PATH "${SILKWORM_BUILD_DIR}" "${COMMAND}")
  message("Running ${COMMAND_REL_PATH}...")

  execute_process(COMMAND "${COMMAND}" "--help" COMMAND_ERROR_IS_FATAL ANY)
endforeach()
