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

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

find_package(absl REQUIRED)
find_package(GTest REQUIRED)
find_package(magic_enum REQUIRED)

set(SILKWORM_SYNC_PUBLIC_LIBS
    absl::btree
    absl::flat_hash_map
    absl::flat_hash_set
    mdbx-static
    silkworm_core
    silkworm_execution
    silkworm_rpcdaemon
    silkworm_sentry
)

# cmake-format: off
set(SILKWORM_SYNC_PRIVATE_LIBS
    cborcpp
    evmone
    magic_enum::magic_enum
)
# cmake-format: on

silkworm_library(
  silkworm_sync
  PUBLIC ${SILKWORM_SYNC_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_SYNC_PRIVATE_LIBS}
)

target_link_libraries(
  silkworm_sync_test PRIVATE GTest::gmock silkworm_db_test_util silkworm_infra_test_util silkworm_rpcdaemon_test_util
)
