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

SET(COPYRIGHT_HEADER
"/*
   Copyright 2022 The Silkworm Authors

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
")

function(check file_path)
    string(LENGTH "${COPYRIGHT_HEADER}" header_len)
    file(READ "${file_path}" header LIMIT ${header_len})

    if(NOT (header STREQUAL COPYRIGHT_HEADER))
        message(SEND_ERROR "${file_path}: the copyright header differs from the other files")
    endif()
endfunction()

cmake_policy(SET CMP0009 NEW)
file(
    GLOB_RECURSE SRC
    LIST_DIRECTORIES false
    "cmd/*.?pp"
    "core/*.?pp"
    "node/*.?pp"
    "sentry/*.?pp"
    "wasm/*.?pp"
)
list(FILTER SRC EXCLUDE REGEX "core/silkworm/chain/genesis_[a-z]+\\.cpp\$")
list(FILTER SRC EXCLUDE REGEX "core/silkworm/common/lru_cache(_test)?\\..pp\$")
list(FILTER SRC EXCLUDE REGEX "node/silkworm/concurrency/thread_pool\\.hpp\$")
list(FILTER SRC EXCLUDE REGEX "node/silkworm/downloader/internals/preverified_hashes_[a-z]+\\.cpp\$")

foreach(F IN LISTS SRC)
    check("${F}")
endforeach()
