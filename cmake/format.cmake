# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} OS_NAME)
set(ARCH_NAME x64)

find_program(
  CLANG_FORMAT clang-format
  PATHS "third_party/clang-format/${OS_NAME}-${ARCH_NAME}"
  NO_SYSTEM_ENVIRONMENT_PATH
)

cmake_policy(SET CMP0009 NEW)
file(
  GLOB_RECURSE SRC
  LIST_DIRECTORIES false
  "cmd/*.?pp" "silkworm/*.?pp"
)
list(FILTER SRC EXCLUDE REGEX "silkworm/interfaces/")
list(FILTER SRC EXCLUDE REGEX "silkworm/core/chain/genesis_[a-z_]+.cpp\$")
list(FILTER SRC EXCLUDE REGEX "silkworm/core/chain/dao.hpp$")
list(FILTER SRC EXCLUDE REGEX "silkworm/rpc/json_rpc/specification.cpp\$")
list(FILTER SRC EXCLUDE REGEX "silkworm/sync/internals/preverified_hashes/preverified_hashes_[a-z]+.cpp\$")

execute_process(COMMAND ${CLANG_FORMAT} -style=file -i ${SRC} COMMAND_ERROR_IS_FATAL ANY)
