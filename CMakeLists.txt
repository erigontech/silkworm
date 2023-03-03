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

# ethash requires cmake 3.16.2
cmake_minimum_required(VERSION 3.16.2)

option(CONAN_PACKAGE_MANAGER "Use Conan.io as package manager" OFF)

if(CONAN_PACKAGE_MANAGER) # CMAKE CONAN START
  message("Package manager: Conan")

  set(CONAN_BINARY_DIR "${CMAKE_BINARY_DIR}/conan")
  list(APPEND CMAKE_MODULE_PATH ${CONAN_BINARY_DIR})
  list(APPEND CMAKE_PREFIX_PATH ${CONAN_BINARY_DIR})
  
  set(CMAKE_CXX_STANDARD 20)
  
  if(NOT EXISTS "${CONAN_BINARY_DIR}/conan.cmake")
    message(STATUS "Downloading conan.cmake from https://github.com/conan-io/cmake-conan")
    file(DOWNLOAD "https://raw.githubusercontent.com/conan-io/cmake-conan/0.18.1/conan.cmake"
            "${CONAN_BINARY_DIR}/conan.cmake"
            TLS_VERIFY ON)
  endif()
  
  include(${CONAN_BINARY_DIR}/conan.cmake)

  # provide a static conanfile.txt instead of generating it with conan_cmake_configure()
  file(COPY "${CMAKE_CURRENT_SOURCE_DIR}/conanfile.txt" DESTINATION "${CONAN_BINARY_DIR}")

  if(NOT DEFINED CONAN_PROFILE)
    message(STATUS "CONAN_PROFILE not defined. Use autodetect settings...")
    conan_cmake_autodetect(CONAN_SETTINGS)
    conan_cmake_install(PATH_OR_REFERENCE "${CONAN_BINARY_DIR}"
          INSTALL_FOLDER "${CONAN_BINARY_DIR}"
          BUILD missing
          REMOTE conancenter
          SETTINGS ${CONAN_SETTINGS})
  else()
    message(STATUS "CONAN_PROFILE: ${CONAN_PROFILE}")
    conan_cmake_install(PATH_OR_REFERENCE "${CONAN_BINARY_DIR}"
          INSTALL_FOLDER "${CONAN_BINARY_DIR}"
          BUILD missing
          REMOTE conancenter
          PROFILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/profiles/${CONAN_PROFILE})
  endif()
endif() # CMAKE CONAN END

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/evmone/evmc/.git)
  message(FATAL_ERROR "Git submodules not initialized, execute:\n  git submodule update --init --recursive")
endif()

get_directory_property(SILKWORM_HAS_PARENT PARENT_DIRECTORY)
if(NOT SILKWORM_HAS_PARENT)
  include(third_party/evmone/cmake/cable/bootstrap.cmake)
  include(CableBuildType)
  cable_set_build_type(DEFAULT Release CONFIGURATION_TYPES Release Debug)

  if(NOT CMAKE_TOOLCHAIN_FILE)
    set(CMAKE_TOOLCHAIN_FILE ${CMAKE_CURRENT_SOURCE_DIR}/cmake/toolchain/cxx20.cmake CACHE FILEPATH "" FORCE)
  endif()

  if(CONAN_PACKAGE_MANAGER)
    set(HUNTER_CONFIG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/HunterAndConan/config.cmake")
  else()
    set(HUNTER_CONFIG_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/config.cmake")
  endif()

  include(third_party/evmone/cmake/cable/HunterGate.cmake)
  # https://github.com/cpp-pm/hunter/releases/
  HunterGate(
    URL "https://github.com/cpp-pm/hunter/archive/v0.24.15.tar.gz"
    SHA1 "8010d63d5ae611c564889d5fe12d3cb7a45703ac"
    FILEPATH "${HUNTER_CONFIG_PATH}"
  )
endif()

#[[
If you want to include Silkworm into your CMake project,
add the following lines before the project command of your root CMakeLists.txt:

-----------------------------------------------------------------------------------------------------
include(silkworm/third_party/evmone/cmake/cable/bootstrap.cmake)
include(silkworm/third_party/evmone/cmake/cable/HunterGate.cmake)
HunterGate(
  URL "https://github.com/cpp-pm/hunter/archive/v0.24.15.tar.gz"
  SHA1 "8010d63d5ae611c564889d5fe12d3cb7a45703ac"
  FILEPATH "${CMAKE_SOURCE_DIR}/silkworm/cmake/Hunter/config.cmake"
)

-----------------------------------------------------------------------------------------------------

(You can update the Hunter version, but keep the FILEPATH option.)
]]

project(silkworm)
set(PROJECT_VERSION 0.1.0-dev)

include(CableBuildInfo)

string(REGEX MATCH "([0-9]+)\\.([0-9]+)\\.([0-9]+)" _ ${PROJECT_VERSION})
set(PROJECT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(PROJECT_VERSION_MINOR ${CMAKE_MATCH_2})
set(PROJECT_VERSION_PATCH ${CMAKE_MATCH_3})

cable_add_buildinfo_library(PROJECT_NAME ${PROJECT_NAME})

option(SILKWORM_WASM_API "Build WebAssembly API" OFF)
option(SILKWORM_CORE_ONLY "Only build Silkworm Core" OFF)
option(SILKWORM_CLANG_COVERAGE "Clang instrumentation for code coverage reports" OFF)
option(SILKWORM_SANITIZE "Build instrumentation for sanitizers" OFF)

get_filename_component(SILKWORM_MAIN_DIR . ABSOLUTE)
set(SILKWORM_MAIN_SRC_DIR "${SILKWORM_MAIN_DIR}/silkworm")

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/compiler_settings.cmake)

# Include dependencies handled by Hunter package manager
if(CONAN_PACKAGE_MANAGER)
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/HunterAndConan/core_packages.cmake)
else()
  include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/core_packages.cmake)
  if(NOT SILKWORM_CORE_ONLY)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/Hunter/extra_packages.cmake)
  endif()
endif()

if(NOT SILKWORM_CORE_ONLY)
  # Silence CMake policy warnings in submodules

  set(CMAKE_POLICY_DEFAULT_CMP0048 NEW) # project() command manages VERSION variables
  set(CMAKE_POLICY_DEFAULT_CMP0063 NEW) # Honor visibility properties for all target types

  # Roaring Bitmaps
  option(ENABLE_ROARING_TESTS "" OFF)
  option(ROARING_BUILD_STATIC "Build a static library" ON)
  if(NOT MSVC)
    # Not supported on MSVC
    option(ROARING_LINK_STATIC "Link executables (tests, benchmarks) statically" ON)
  endif()
  add_subdirectory(third_party/CRoaring EXCLUDE_FROM_ALL)

  # CBOR
  add_subdirectory(third_party/cbor-cpp)
    
endif()

# evmone with dependencies
if(SILKWORM_WASM_API)
  add_compile_definitions(EVMC_LOADER_MOCK)
endif()

find_package(intx REQUIRED)   # Required from here below
find_package(ethash REQUIRED) # Required from here below

add_subdirectory(third_party/evmone/evmc)

add_library(evmone third_party/evmone/lib/evmone/advanced_analysis.cpp
                   third_party/evmone/lib/evmone/advanced_analysis.hpp
                   third_party/evmone/lib/evmone/advanced_execution.cpp
                   third_party/evmone/lib/evmone/advanced_execution.hpp
                   third_party/evmone/lib/evmone/advanced_instructions.cpp
                   third_party/evmone/lib/evmone/baseline_instruction_table.cpp
                   third_party/evmone/lib/evmone/baseline_instruction_table.hpp
                   third_party/evmone/lib/evmone/baseline.cpp
                   third_party/evmone/lib/evmone/baseline.hpp
                   third_party/evmone/lib/evmone/eof.cpp
                   third_party/evmone/lib/evmone/eof.hpp
                   third_party/evmone/lib/evmone/execution_state.hpp
                   third_party/evmone/lib/evmone/instructions_calls.cpp
                   third_party/evmone/lib/evmone/instructions_opcodes.hpp
                   third_party/evmone/lib/evmone/instructions_storage.cpp
                   third_party/evmone/lib/evmone/instructions_traits.hpp
                   third_party/evmone/lib/evmone/instructions_xmacro.hpp
                   third_party/evmone/lib/evmone/instructions.hpp
                   third_party/evmone/lib/evmone/opcodes_helpers.h
                   third_party/evmone/lib/evmone/tracing.cpp
                   third_party/evmone/lib/evmone/tracing.hpp
                   third_party/evmone/lib/evmone/vm.cpp
                   third_party/evmone/lib/evmone/vm.hpp)
set_source_files_properties(third_party/evmone/lib/evmone/vm.cpp PROPERTIES COMPILE_DEFINITIONS PROJECT_VERSION="0.10.0-dev")
target_include_directories(evmone PUBLIC third_party/evmone/include third_party/evmone/lib)
target_link_libraries(evmone PUBLIC evmc intx::intx PRIVATE evmc::instructions)

if(MSVC)
  target_compile_options(evmone PRIVATE /EHsc /w)
else()
  target_compile_options(evmone PRIVATE -fno-exceptions)
endif()

# MDBX
if(NOT SILKWORM_CORE_ONLY)
  set(MDBX_ENABLE_TESTS OFF)
  add_subdirectory(third_party/libmdbx)
  target_include_directories(mdbx-static INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/third_party/libmdbx)
endif()

if(NOT MSVC)
  set(GMP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/gmplib")
  set(GMP_INSTALL_DIR "${CMAKE_BINARY_DIR}/third_party/gmplib")

  set(GMP_INCLUDE_DIR "${GMP_INSTALL_DIR}" CACHE PATH "")
  set(GMP_LIBRARY "${GMP_INSTALL_DIR}/lib/libgmp.a" CACHE FILEPATH "")

  include(ExternalProject)
  ExternalProject_Add(
    gmplib
    SOURCE_DIR "${GMP_SOURCE_DIR}"
    BINARY_DIR "${GMP_INSTALL_DIR}"
    CONFIGURE_COMMAND "${GMP_SOURCE_DIR}/configure"
      "--prefix=${GMP_INSTALL_DIR}"
      --with-pic=yes
    PREFIX "${GMP_INSTALL_DIR}"
    BUILD_BYPRODUCTS "${GMP_LIBRARY}"
  )
endif()

# libtorrent
if(NOT SILKWORM_CORE_ONLY)
  find_package(Boost REQUIRED)
  # Define Boost::headers target if missing because libtorrent needs it
  if(NOT TARGET Boost::headers)
    add_library(Boost::headers INTERFACE IMPORTED)
    target_include_directories(Boost::headers INTERFACE ${Boost_INCLUDE_DIRS})
  endif()
  add_subdirectory(third_party/libtorrent)
  target_compile_options(torrent-rasterbar PRIVATE -w)
endif()

add_subdirectory(third_party/silkpre)
add_subdirectory(third_party/tomlplusplus)

if(NOT MSVC)
  add_dependencies(silkpre gmplib)
  add_dependencies(ff gmplib)
endif()

# Compiler enforcements on Silkworm
if(NOT MSVC)
  add_compile_options(-Werror -Wall -Wextra -pedantic)
  add_compile_options(-Wshadow -Wimplicit-fallthrough -Wsign-conversion)
  add_compile_options($<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>)
  add_compile_options(-Wno-missing-field-initializers -Wnon-virtual-dtor)

  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    add_compile_options(-Wno-attributes)

    # coroutines support
    if((CMAKE_CXX_STANDARD GREATER_EQUAL 20) AND (NOT SILKWORM_WASM_API))
      add_compile_options(-fcoroutines)
    endif()
  endif()

  if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_SYSTEM_NAME MATCHES "Darwin")
    add_compile_definitions(_LIBCPP_ENABLE_THREAD_SAFETY_ANNOTATIONS)
    add_compile_options(-Wthread-safety)
  endif()
endif()

# Silkworm itself
add_subdirectory(silkworm)

if(NOT SILKWORM_HAS_PARENT)
  add_subdirectory(cmd)
endif()
