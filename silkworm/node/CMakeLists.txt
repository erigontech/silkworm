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

add_subdirectory(stagedsync/stages)

find_package(absl REQUIRED strings)
find_package(asio-grpc REQUIRED)
find_package(Boost REQUIRED headers)
find_package(gRPC REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Microsoft.GSL REQUIRED)
find_package(Protobuf REQUIRED)

set(SILKWORM_NODE_PUBLIC_LIBS
    silkworm_core
    silkworm_db
    silkworm_infra
    silkworm_sentry
    silkworm_snapshots
    asio-grpc::asio-grpc
    Boost::headers
    gRPC::grpc++
    protobuf::libprotobuf
)

# cmake-format: off
set(SILKWORM_NODE_PRIVATE_LIBS
    absl::strings
    evmone
    magic_enum::magic_enum
    Microsoft.GSL::GSL
    silkworm_db_etl
    silkworm_interfaces
    silkworm_stages
)
# cmake-format: on

silkworm_library(
  silkworm_node
  PUBLIC ${SILKWORM_NODE_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_NODE_PRIVATE_LIBS}
)
