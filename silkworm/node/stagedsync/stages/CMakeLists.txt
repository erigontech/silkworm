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

find_package(absl REQUIRED btree)
# circular_buffer
find_package(Boost REQUIRED headers)
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)

set(LIBS_PUBLIC
    Boost::headers
    ethash::keccak
    evmc
    secp256k1
    silkworm_core
    silkworm_db
    silkworm_db_etl
    silkworm_infra
)

# cmake-format: off
set(LIBS_PRIVATE
    absl::btree
    magic_enum::magic_enum
    Microsoft.GSL::GSL
)
# cmake-format: on

silkworm_library(
  silkworm_stages
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)
