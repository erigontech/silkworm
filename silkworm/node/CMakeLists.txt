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

find_package(absl REQUIRED)
find_package(asio-grpc REQUIRED)
find_package(Boost REQUIRED headers container)
find_package(nlohmann_json REQUIRED)
find_package(gRPC REQUIRED)
find_package(magic_enum REQUIRED)
find_package(Protobuf REQUIRED)
find_package(roaring REQUIRED)

if(SILKWORM_CLANG_TIDY)
  set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY};-warnings-as-errors=*")
endif()

file(
  GLOB_RECURSE
  SILKWORM_NODE_SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.hpp"
  "*.c"
  "*.h"
  "*.cc"
)
list(FILTER SILKWORM_NODE_SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SILKWORM_NODE_SRC EXCLUDE REGEX "_benchmark\\.cpp$")

add_library(silkworm_node "${SILKWORM_NODE_SRC}")

target_include_directories(silkworm_node PUBLIC "${SILKWORM_MAIN_DIR}")

set(SILKWORM_NODE_PUBLIC_LIBS
    silkworm_core
    silkworm_infra
    silkworm_sentry
    absl::btree
    absl::flat_hash_map
    absl::flat_hash_set
    asio-grpc::asio-grpc
    Boost::container
    Boost::headers
    gRPC::grpc++
    mdbx-static
    nlohmann_json::nlohmann_json
    protobuf::libprotobuf
    roaring::roaring
    torrent-rasterbar
)

# cmake-format: off
set(SILKWORM_NODE_PRIVATE_LIBS
    cborcpp
    evmone
    magic_enum::magic_enum
    silkworm_interfaces
)
# cmake-format: on
if(MSVC)
  list(APPEND SILKWORM_NODE_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(
  silkworm_node
  PUBLIC ${SILKWORM_NODE_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_NODE_PRIVATE_LIBS}
)
