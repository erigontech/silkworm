#[[
   Copyright 2024 The Silkworm Authors

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
find_package(roaring REQUIRED)

silkworm_library(
  silkworm_datastore_kvdb
  PUBLIC absl::btree
         absl::function_ref
         roaring::roaring
         mdbx-static
         silkworm_core
         silkworm_infra
         silkworm_datastore_common
         silkworm_datastore_etl
)

target_link_libraries(silkworm_datastore_kvdb_test PRIVATE silkworm_infra_test_util)
