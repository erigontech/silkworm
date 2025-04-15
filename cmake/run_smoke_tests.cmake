# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

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
  "${SILKWORM_BUILD_DIR}/*${CMAKE_EXECUTABLE_SUFFIX}"
)
list(FILTER COMMANDS INCLUDE REGEX "(cli|cmd)/")
if(NOT CMAKE_EXECUTABLE_SUFFIX)
  list(FILTER COMMANDS EXCLUDE REGEX "\\.")
endif()
list(FILTER COMMANDS EXCLUDE REGEX "Makefile")

# TODO: fix check_log_indices --help
list(FILTER COMMANDS EXCLUDE REGEX "check_log_indices")
# Skip smoke test for execute in ASAN build due to odr-violation
if(NOT SILKWORM_SANITIZE)
  # TODO: fix execute ASAN odr-violation
  list(FILTER COMMANDS EXCLUDE REGEX "execute")
endif()
# TODO: fix grpc_toolbox --help
list(FILTER COMMANDS EXCLUDE REGEX "grpc_toolbox")
# TODO: fix sentry_client_test --help
list(FILTER COMMANDS EXCLUDE REGEX "sentry_client_test")

message("")
message("===================")
message("Running smoke tests")
message("===================")
message("")

foreach(COMMAND IN LISTS COMMANDS)
  file(RELATIVE_PATH COMMAND_REL_PATH "${SILKWORM_BUILD_DIR}" "${COMMAND}")
  message("Running ${COMMAND_REL_PATH} --help ...")

  execute_process(COMMAND "${COMMAND}" "--help" OUTPUT_QUIET COMMAND_ERROR_IS_FATAL ANY)
endforeach()
