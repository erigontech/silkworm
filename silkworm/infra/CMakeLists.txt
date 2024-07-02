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

add_subdirectory(test_util)

set(TARGET silkworm_infra)

find_package(absl REQUIRED)
find_package(asio-grpc REQUIRED)
find_package(Boost REQUIRED headers container thread)
find_package(Catch2 REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)
find_package(magic_enum REQUIRED)
find_package(spdlog REQUIRED)

file(GLOB_RECURSE SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp")
list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SRC EXCLUDE REGEX "_benchmark\\.cpp$")
list(FILTER SRC EXCLUDE REGEX "test_util/")

add_library(${TARGET} "${SRC}")

target_include_directories(${TARGET} PUBLIC "${SILKWORM_MAIN_DIR}")

set(LIBS_PUBLIC
    silkworm_core
    silkworm_interfaces
    absl::strings
    asio-grpc::asio-grpc
    Boost::headers
    Boost::thread
    gRPC::grpc++
)

# cmake-format: off
set(LIBS_PRIVATE
    absl::time
    Boost::container # required for asio-grpc
    magic_enum::magic_enum
    spdlog::spdlog
    silkworm-buildinfo
)
# cmake-format: on

target_link_libraries(
  ${TARGET}
  PUBLIC "${LIBS_PUBLIC}"
  PRIVATE "${LIBS_PRIVATE}"
)

# unit tests
set(TEST_TARGET ${TARGET}_test)
file(GLOB_RECURSE TEST_SRC CONFIGURE_DEPENDS "*_test.cpp")
add_executable(${TEST_TARGET} ${TEST_SRC})
target_link_libraries(
  ${TEST_TARGET}
  PRIVATE ${TARGET} Catch2::Catch2WithMain GTest::gmock
  silkworm_infra_test_util
)
