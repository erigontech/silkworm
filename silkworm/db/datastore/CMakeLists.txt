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

add_subdirectory(common)
add_subdirectory(etl)
add_subdirectory(kvdb)
add_subdirectory(snapshots)

find_package(Boost REQUIRED COMPONENTS headers)

# cmake-format: off
set(LIBS_PUBLIC
    Boost::headers
    silkworm_core
    silkworm_infra
    silkworm_datastore_common
    silkworm_datastore_kvdb
    silkworm_snapshots
)
# cmake-format: on

# cmake-format: off
set(LIBS_PRIVATE
)
# cmake-format: on

silkworm_library(
  silkworm_datastore
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)
