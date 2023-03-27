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

string(TOLOWER ${CMAKE_HOST_SYSTEM_NAME} OS_NAME)

if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "")
  set(ARCH_NAME x64)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL x86_64)
  set(ARCH_NAME x64)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL IA64)
  set(ARCH_NAME x64)
elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL AMD64)
  set(ARCH_NAME x64)
endif()

find_program(
  CLANG_FORMAT clang-format
  PATHS "third_party/clang-format/${OS_NAME}-${ARCH_NAME}"
  NO_SYSTEM_ENVIRONMENT_PATH
)

cmake_policy(SET CMP0009 NEW)
file(
  GLOB_RECURSE SRC
  LIST_DIRECTORIES false
  "cmd/*.?pp" "silkworm/*.?pp"
)
list(FILTER SRC EXCLUDE REGEX "silkworm/interfaces/")
list(FILTER SRC EXCLUDE REGEX "silkworm/core/chain/genesis_[a-z]+.cpp\$")
list(FILTER SRC EXCLUDE REGEX "silkworm/core/chain/dao.hpp$")
list(FILTER SRC EXCLUDE REGEX "silkworm/node/common/preverified_hashes_[a-z]+.cpp\$")
list(FILTER SRC EXCLUDE REGEX "silkworm/node/snapshot/config/[a-z_]+.cpp\$")
list(FILTER SRC EXCLUDE REGEX "silkworm/node/snapshot/toml.hpp$$")

execute_process(COMMAND ${CLANG_FORMAT} -style=file -i ${SRC})
