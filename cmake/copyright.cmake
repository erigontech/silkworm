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

set(COPYRIGHT_HEADER_TEMPLATE
    "/*
   Copyright YYYY The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the \"License\");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an \"AS IS\" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
"
)

set(SILKWORM_COPYRIGHT_YEARS "2022" "2023" "2024" "2025")

function(check file_path)
  string(LENGTH "${COPYRIGHT_HEADER_TEMPLATE}" header_len)
  file(READ "${file_path}" header LIMIT ${header_len})

  foreach(Y IN LISTS SILKWORM_COPYRIGHT_YEARS)
    string(REPLACE "YYYY" "${Y}" COPYRIGHT_HEADER "${COPYRIGHT_HEADER_TEMPLATE}")

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
  "cmd/*.?pp" "silkworm/*.?pp"
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
  check("${F}")
endforeach()
