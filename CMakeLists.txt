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

include("cmake/HunterGate.cmake")
HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.23.257.tar.gz"
    SHA1 "52203b35dfc2f975f4c22fc89f055476726e4288"
)

project(silkworm)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -pedantic -Wno-c99-extensions -Werror)
endif()

set(SILKWORM_LIBS silkworm_db silkworm_rlp silkworm_eth)

add_subdirectory(db)
add_subdirectory(rlp)
add_subdirectory(eth)
add_subdirectory(tests)

add_executable(silkworm silkworm.cpp)
target_include_directories(silkworm PUBLIC "${PROJECT_SOURCE_DIR}")
target_link_libraries(silkworm PUBLIC "${SILKWORM_LIBS}")
