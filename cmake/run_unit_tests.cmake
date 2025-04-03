# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

if(NOT SILKWORM_BUILD_DIR)
  set(SILKWORM_BUILD_DIR "${CMAKE_CURRENT_LIST_DIR}/../build")
endif()
file(REAL_PATH "${SILKWORM_BUILD_DIR}" SILKWORM_BUILD_DIR)

if(NOT SILKWORM_PROJECT_DIR)
  set(SILKWORM_PROJECT_DIR "${CMAKE_CURRENT_LIST_DIR}/..")
endif()
file(REAL_PATH "${SILKWORM_PROJECT_DIR}" SILKWORM_PROJECT_DIR)

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  set(CMAKE_EXECUTABLE_SUFFIX ".exe")
endif()

file(
  GLOB_RECURSE TEST_COMMANDS
  LIST_DIRECTORIES false
  "${SILKWORM_BUILD_DIR}/*_test${CMAKE_EXECUTABLE_SUFFIX}"
)

list(FILTER TEST_COMMANDS EXCLUDE REGEX "backend_kv_test${CMAKE_EXECUTABLE_SUFFIX}\$")
list(FILTER TEST_COMMANDS EXCLUDE REGEX "benchmark_test${CMAKE_EXECUTABLE_SUFFIX}\$")
list(FILTER TEST_COMMANDS EXCLUDE REGEX "sentry_client_test${CMAKE_EXECUTABLE_SUFFIX}\$")

message("")
message("==================")
message("Running unit tests")
message("==================")
message("")

string(TIMESTAMP TIME "%s")
message("For all tests --rng-seed=${TIME}")
message("")

if("${SILKWORM_SANITIZE}" STREQUAL "thread")
  set(ENV{TSAN_OPTIONS} "suppressions=${SILKWORM_PROJECT_DIR}/tools/sanitizer/tsan_suppressions.txt")
endif()

foreach(TEST_COMMAND IN LISTS TEST_COMMANDS)
  file(RELATIVE_PATH TEST_COMMAND_REL_PATH "${SILKWORM_BUILD_DIR}" "${TEST_COMMAND}")
  message("Running ${TEST_COMMAND_REL_PATH}...")

  if(SILKWORM_CLANG_COVERAGE)
    get_filename_component(TEST_COMMAND_NAME "${TEST_COMMAND}" NAME)
    set(ENV{LLVM_PROFILE_FILE} "${TEST_COMMAND_NAME}.profraw")
  endif()

  execute_process(COMMAND "${TEST_COMMAND}" "--rng-seed=${TIME}" "--min-duration=2" RESULT_VARIABLE EXIT_CODE)
  if(NOT (EXIT_CODE EQUAL 0))
    message(FATAL_ERROR "${TEST_COMMAND_REL_PATH} has failed: ${EXIT_CODE}")
  endif()
endforeach()
