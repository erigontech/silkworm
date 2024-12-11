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
find_package(Boost REQUIRED COMPONENTS headers)
find_package(gRPC REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Snappy REQUIRED)

# sentry common
add_subdirectory(common)

# discovery common
add_subdirectory(discovery/common)

# node DB
add_subdirectory(discovery/node_db)

# ENR
add_subdirectory(discovery/enr)

# disc v4
add_subdirectory(discovery/disc_v4)

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

# cmake-format: off
set(LIBS_PUBLIC
    Boost::headers
    Microsoft.GSL::GSL
    silkworm_infra
)
# cmake-format: on

silkworm_library(
  silkworm_sentry
  PUBLIC ${LIBS_PUBLIC}
  PRIVATE ${LIBS_PRIVATE}
)

# silkworm_sentry_cli depends on silkworm_sentry
add_subdirectory(cli)
