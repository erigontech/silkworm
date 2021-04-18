#[[
   Copyright 2020 The Silkworm Authors

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

find_package(absl CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED COMPONENTS filesystem)
find_package(nlohmann_json CONFIG REQUIRED)

add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_mainnet.cpp"
    COMMAND ${CMAKE_COMMAND} ARGS
    -DBIN2H_SOURCE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/silkworm/common/genesis_mainnet.json"
    -DBIN2H_VARIABLE_NAME="genesis_mainnet_data"
    -DBIN2H_HEADER_FILE="${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_mainnet.cpp"
    -DBIN2H_REMOVE_LEADING_WHITESPACE=1
    -DBIN2H_REMOVE_TRAILING_WHITESPACE=1
    -DBIN2H_REMOVE_EMPTY_LINES=1
    -DBIN2H_CONDENSE_WHITESPACE=1
    -P "${CMAKE_CURRENT_SOURCE_DIR}/bin2h.cmake"
    COMMENT "Generating Mainnet Genesis Byte Array"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/silkworm/common/genesis_mainnet.json"
)

add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_goerli.cpp"
    COMMAND ${CMAKE_COMMAND} ARGS
    -DBIN2H_SOURCE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/silkworm/common/genesis_goerli.json"
    -DBIN2H_VARIABLE_NAME="genesis_goerli_data"
    -DBIN2H_HEADER_FILE="${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_goerli.cpp"
    -DBIN2H_REMOVE_LEADING_WHITESPACE=1
    -DBIN2H_REMOVE_TRAILING_WHITESPACE=1
    -DBIN2H_REMOVE_EMPTY_LINES=1
    -DBIN2H_CONDENSE_WHITESPACE=1
    -P "${CMAKE_CURRENT_SOURCE_DIR}/bin2h.cmake"
    COMMENT "Generating Goerli  Genesis Byte Array"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/silkworm/common/genesis_goerli.json"
)

add_custom_command(
    OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_rinkeby.cpp"
    COMMAND ${CMAKE_COMMAND} ARGS
    -DBIN2H_SOURCE_FILE="${CMAKE_CURRENT_SOURCE_DIR}/silkworm/common/genesis_rinkeby.json"
    -DBIN2H_VARIABLE_NAME="genesis_rinkeby_data"
    -DBIN2H_HEADER_FILE="${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_rinkeby.cpp"
    -DBIN2H_REMOVE_LEADING_WHITESPACE=1
    -DBIN2H_REMOVE_TRAILING_WHITESPACE=1
    -DBIN2H_REMOVE_EMPTY_LINES=1
    -DBIN2H_CONDENSE_WHITESPACE=1
    -P "${CMAKE_CURRENT_SOURCE_DIR}/bin2h.cmake"
    COMMENT "Generating Rinkeby Genesis Byte Array"
    DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/silkworm/common/genesis_rinkeby.json"
)

file(GLOB_RECURSE SILKWORM_DB_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h")
list(FILTER SILKWORM_DB_SRC EXCLUDE REGEX "_test\.cpp$")
list(APPEND SILKWORM_DB_SRC "${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_mainnet.cpp"
                            "${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_goerli.cpp"
                            "${CMAKE_CURRENT_BINARY_DIR}/silkworm/common/genesis_rinkeby.cpp")

add_library(silkworm_db ${SILKWORM_DB_SRC})
target_include_directories(silkworm_db PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

set(SILKWORM_DB_PUBLIC_LIBS silkworm_core lmdb absl::flat_hash_map absl::flat_hash_set absl::btree Boost::filesystem roaring nlohmann_json::nlohmann_json)
set(SILKWORM_DB_PRIVATE_LIBS cborcpp)

if(MSVC)
  list(APPEND SILKWORM_DB_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm_db PUBLIC ${SILKWORM_DB_PUBLIC_LIBS} PRIVATE ${SILKWORM_DB_PRIVATE_LIBS})
