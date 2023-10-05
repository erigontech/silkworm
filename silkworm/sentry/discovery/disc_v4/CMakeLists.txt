#[[
   Copyright 2023 The Silkworm Authors

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

find_package(Boost REQUIRED headers)

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

silkworm_library(
  silkworm_sentry_disc_v4
  PUBLIC silkworm_infra silkworm_sentry_common silkworm_sentry_node_db silkworm_sentry_discovery_enr
  PRIVATE Boost::headers stbrumme_keccak silkworm_core silkworm_sentry_discovery_common
)
