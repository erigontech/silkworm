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

find_package(Boost REQUIRED headers)
find_package(CLI11 REQUIRED)

# Generate source files containing snapshot TOML files as binary data
set(SILKWORM_EMBED embed)
find_package(CLI11 REQUIRED)
add_executable(${SILKWORM_EMBED} ${SILKWORM_MAIN_DIR}/cmd/dev/embed.cpp)
target_link_libraries(${SILKWORM_EMBED} PRIVATE CLI11::CLI11 Boost::headers)

set(SILKWORM_TOML_SRC_DIR "${SILKWORM_MAIN_DIR}/third_party/erigon-snapshot")
set(SILKWORM_TOML_SRC
    ${SILKWORM_TOML_SRC_DIR}/bor-mainnet.toml
    # ${SILKWORM_TOML_SRC_DIR}/chiado.toml
    ${SILKWORM_TOML_SRC_DIR}/gnosis.toml
    ${SILKWORM_TOML_SRC_DIR}/goerli.toml
    ${SILKWORM_TOML_SRC_DIR}/mainnet.toml
    ${SILKWORM_TOML_SRC_DIR}/mumbai.toml
    ${SILKWORM_TOML_SRC_DIR}/ropsten.toml
    ${SILKWORM_TOML_SRC_DIR}/sepolia.toml
)
set(SILKWORM_TOML_CPP_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
set(SILKWORM_TOML_CPP_SRC
    ${SILKWORM_TOML_CPP_SRC_DIR}/bor_mainnet.cpp
    # ${SILKWORM_TOML_CPP_SRC_DIR}/chiado.cpp
    ${SILKWORM_TOML_CPP_SRC_DIR}/gnosis.cpp
    ${SILKWORM_TOML_CPP_SRC_DIR}/goerli.cpp
    ${SILKWORM_TOML_CPP_SRC_DIR}/mainnet.cpp
    ${SILKWORM_TOML_CPP_SRC_DIR}/mumbai.cpp
    ${SILKWORM_TOML_CPP_SRC_DIR}/ropsten.cpp
    ${SILKWORM_TOML_CPP_SRC_DIR}/sepolia.cpp
)

add_custom_command(
  OUTPUT "${SILKWORM_TOML_CPP_SRC}"
  COMMAND "${SILKWORM_EMBED}" ARGS -i "${SILKWORM_TOML_SRC_DIR}" -o "${SILKWORM_TOML_CPP_SRC_DIR}" -e ".toml" -s "toml"
  DEPENDS "${SILKWORM_EMBED}" "${SILKWORM_TOML_SRC}"
)

add_custom_target(generate_toml ALL DEPENDS "${SILKWORM_TOML_CPP_SRC}" "${SILKWORM_EMBED}")

add_library(silkworm_node_snapshot_config "${SILKWORM_TOML_CPP_SRC}")
add_dependencies(silkworm_node_snapshot_config generate_toml)
