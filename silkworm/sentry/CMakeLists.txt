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

set(TARGET silkworm_sentry)

find_package(absl REQUIRED)
find_package(Boost REQUIRED headers)
find_package(Catch2 REQUIRED)
find_package(gRPC REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Snappy REQUIRED)

# sentry common
add_subdirectory(common)

# node DB
add_subdirectory(discovery/node_db)

# discovery common
add_subdirectory(discovery/common)

# ENR
add_subdirectory(discovery/enr)

# disc v4
add_subdirectory(discovery/disc_v4)

set(SRC "")
file(
  GLOB_RECURSE
  SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.hpp"
  "*.c"
  "*.h"
  "*.cc"
)
list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SRC EXCLUDE REGEX "sentry/common")
list(FILTER SRC EXCLUDE REGEX "discovery/[a-z0-9_]+/")

add_library(${TARGET} ${SRC})

target_include_directories(${TARGET} PUBLIC "${SILKWORM_MAIN_DIR}")

set(LIBS_PRIVATE
    gRPC::grpc++
    protobuf::libprotobuf
    OpenSSL::Crypto
    Snappy::snappy
    stbrumme_crc32
    stbrumme_keccak
    stun_msg
    silkworm_core
    silkworm_interfaces
    silkworm-buildinfo
    silkworm_sentry_common
    silkworm_sentry_node_db
    silkworm_sentry_discovery_common
    silkworm_sentry_discovery_enr
    silkworm_sentry_disc_v4
)
if(MSVC)
  list(APPEND LIBS_PRIVATE ntdll.lib)
endif(MSVC)

# cmake-format: off
set(LIBS_PUBLIC
    Boost::headers
    Microsoft.GSL::GSL
    silkworm_infra
)
# cmake-format: on

target_link_libraries(
  ${TARGET}
  PUBLIC "${LIBS_PUBLIC}"
  PRIVATE "${LIBS_PRIVATE}"
)

# unit tests
set(TEST_TARGET sentry_test)
file(GLOB_RECURSE TEST_SRC CONFIGURE_DEPENDS "*_test.cpp")
list(FILTER TEST_SRC EXCLUDE REGEX "sentry/common")
list(FILTER TEST_SRC EXCLUDE REGEX "discovery/")
add_executable(${TEST_TARGET} "${SILKWORM_MAIN_DIR}/cmd/test/unit_test.cpp" ${TEST_SRC})
target_link_libraries(${TEST_TARGET} ${TARGET} Catch2::Catch2)
