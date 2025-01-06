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

find_package(Boost REQUIRED COMPONENTS headers)
find_package(GTest REQUIRED)

silkworm_library(
  silkworm_rpcdaemon_test_util
  PUBLIC silkworm_infra silkworm_rpcdaemon
  PRIVATE silkworm_db_test_util Boost::headers glaze::glaze GTest::gmock
)
