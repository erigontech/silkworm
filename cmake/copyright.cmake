# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

set(COPYRIGHT_HEADER_TEMPLATE_C
    "// Copyright YYYY The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

"
)

set(COPYRIGHT_HEADER_TEMPLATE_SH
    "# Copyright YYYY The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

"
)

set(SILKWORM_COPYRIGHT_YEARS "2025")

function(check file_path template)
  string(LENGTH "${template}" header_len)
  file(READ "${file_path}" header LIMIT ${header_len})

  foreach(Y IN LISTS SILKWORM_COPYRIGHT_YEARS)
    string(REPLACE "YYYY" "${Y}" COPYRIGHT_HEADER "${template}")

    if(header STREQUAL COPYRIGHT_HEADER)
      return()
    endif()
  endforeach()

  message(SEND_ERROR "${file_path}: the copyright header differs from the other files")
endfunction()

cmake_policy(SET CMP0009 NEW)
file(
  GLOB_RECURSE SRC
  LIST_DIRECTORIES false
  "cmd/*.?pp" "examples/*.?pp" "silkworm/*.?pp"
)
list(FILTER SRC EXCLUDE REGEX [[silkworm/core/chain/genesis_[a-z_]+\.cpp$]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/core/common/lru_cache(_test)?\..pp$]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/core/crypto/kzg\.cpp$]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/infra/concurrency/thread_pool\.hpp$]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/interfaces/]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/db/datastore/snapshots/config/chains/[a-z_]+\.hpp$]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/rpc/json_rpc/specification\.cpp$]])
list(FILTER SRC EXCLUDE REGEX [[silkworm/sync/internals/preverified_hashes/preverified_hashes_[a-z]+\.cpp$]])

foreach(F IN LISTS SRC)
  check("${F}" "${COPYRIGHT_HEADER_TEMPLATE_C}")
endforeach()

file(
  GLOB_RECURSE SRC_CMAKE
  LIST_DIRECTORIES false
  "cmake/*.cmake" "cmake/*CMakeLists.txt" "cmd/*CMakeLists.txt" "examples/*CMakeLists.txt" "silkworm/*CMakeLists.txt"
)
list(FILTER SRC_CMAKE EXCLUDE REGEX [[cmake/conan_quiet.cmake$]])

foreach(F IN LISTS SRC_CMAKE)
  check("${F}" "${COPYRIGHT_HEADER_TEMPLATE_SH}")
endforeach()
