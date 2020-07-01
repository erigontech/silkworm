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

cmake_minimum_required(VERSION 3.12) # for CONFIGURE_DEPENDS

include(evmone/cmake/cable/bootstrap.cmake)
include(CableBuildType)
include(CableToolchains)

cable_configure_toolchain(DEFAULT cxx17-pic)
cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

include("evmone/cmake/cable/HunterGate.cmake")
set(HUNTER_USE_CACHE_SERVERS NO)
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.23.258.tar.gz"
  SHA1 "062a19ab13ce8dffa9a882b6ce3e43bdabdf75d3"
  FILEPATH "${CMAKE_CURRENT_SOURCE_DIR}/evmone/cmake/Hunter/config.cmake"
)

project(silkworm)

if(MSVC)
  add_compile_options(/W4 /WX)
else()
  add_compile_options(-Wall -Wextra -Werror)
endif()

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  add_compile_options(-Wno-attributes -Wno-missing-field-initializers)
endif()

set(SILKWORM_LIBS silkworm_db silkworm_eth)

add_subdirectory(evmone)

add_subdirectory(db)
add_subdirectory(eth)

add_subdirectory(tests)

add_executable(silkworm silkworm.cpp)
target_include_directories(silkworm PRIVATE "${PROJECT_SOURCE_DIR}")
target_link_libraries(silkworm PRIVATE "${SILKWORM_LIBS}")
