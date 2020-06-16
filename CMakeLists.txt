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

cmake_minimum_required(VERSION 3.5)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_TOOLCHAIN_FILE ${CMAKE_SOURCE_DIR}/cmake/cxx17.cmake)

include("cmake/Hunter/HunterGate.cmake")
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.257.tar.gz"
  SHA1 "52203b35dfc2f975f4c22fc89f055476726e4288"
  LOCAL
)

project(silkworm LANGUAGES CXX)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -pedantic -Werror)
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  add_compile_options(-Wno-c99-extensions)
endif()

set(SILKWORM_LIBS silkworm_db silkworm_rlp silkworm_eth)

add_subdirectory(db)
add_subdirectory(rlp)
add_subdirectory(eth)
add_subdirectory(tests)

add_executable(silkworm silkworm.cpp)
target_include_directories(silkworm PRIVATE "${PROJECT_SOURCE_DIR}")
target_link_libraries(silkworm PRIVATE "${SILKWORM_LIBS}")
