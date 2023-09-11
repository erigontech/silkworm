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
find_package(Catch2 REQUIRED)

set(TARGET silkworm_sentry_disc_v4)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp")
list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")

add_library(${TARGET} ${SRC})

target_include_directories(${TARGET} PUBLIC "${SILKWORM_MAIN_DIR}")

target_link_libraries(
  ${TARGET}
  PUBLIC silkworm_infra silkworm_sentry_common
  PRIVATE Boost::headers stbrumme_keccak silkworm_core silkworm_sentry_node_db
)

# unit tests
set(TEST_TARGET ${TARGET}_test)
file(GLOB_RECURSE TEST_SRC CONFIGURE_DEPENDS "*_test.cpp")
add_executable(${TEST_TARGET} "${SILKWORM_MAIN_DIR}/cmd/test/unit_test.cpp" ${TEST_SRC})
target_link_libraries(${TEST_TARGET} ${TARGET} Catch2::Catch2)
