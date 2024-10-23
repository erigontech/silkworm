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

include(${CMAKE_CURRENT_LIST_DIR}/compiler_settings_sanitize.cmake)

function(guess_conan_profile)
  if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "")
    set(ARCH_NAME "")
  elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL x86_64)
    set(ARCH_NAME x64)
  elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL IA64)
    set(ARCH_NAME x64)
  elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL AMD64)
    set(ARCH_NAME x64)
  elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL arm64)
    set(ARCH_NAME arm64)
  elseif(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL AArch64)
    set(ARCH_NAME arm64)
  endif()

  if(SILKWORM_WASM_API)
    set(PROFILE wasi_release)
  elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND ARCH_NAME)
    set(PROFILE linux_${ARCH_NAME}_gcc_11_release)
  elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin" AND ARCH_NAME)
    set(PROFILE macos_${ARCH_NAME}_clang_13_release)
  elseif(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
    set(PROFILE windows_msvc_16_release)
  else()
    message(FATAL_ERROR "CONAN_PROFILE is not defined for ${CMAKE_HOST_SYSTEM_NAME} on ${CMAKE_HOST_SYSTEM_PROCESSOR}")
  endif()

  set(CONAN_PROFILE
      ${PROFILE}
      PARENT_SCOPE
  )
endfunction()

function(get_conan_build_type profile_path var)
  file(READ "${profile_path}" CONTENTS)
  string(REGEX MATCH "build_type=[A-Za-z0-9]+" VALUE "${CONTENTS}")
  string(SUBSTRING "${VALUE}" 11 -1 VALUE)
  set(${var}
      "${VALUE}"
      PARENT_SCOPE
  )
endfunction()

find_program(CONAN_COMMAND "conan" PATHS ~/.local/bin REQUIRED)
# set(CONAN_COMMAND "/Users/daniel/Desktop/conan2/bin/conan")

set(CONAN_BINARY_DIR "${CMAKE_BINARY_DIR}/conan2")

if(NOT DEFINED CONAN_PROFILE)
  guess_conan_profile()
endif()
message(STATUS "CONAN_PROFILE: ${CONAN_PROFILE}")
set(CONAN_PROFILE_PATH "${CMAKE_SOURCE_DIR}/cmake/profiles/${CONAN_PROFILE}")
set(CONAN_HOST_PROFILE "${CONAN_PROFILE_PATH}")
set(CONAN_BUILD_PROFILE "${CONAN_PROFILE_PATH}")
get_conan_build_type("${CONAN_PROFILE_PATH}" CONAN_BUILD_TYPE)

set(CONAN_BUILD "missing")
set(CONAN_CXXFLAGS_ARG)
set(CONAN_OPTIONS)

if(SILKWORM_SANITIZE_COMPILER_OPTIONS)
  set(CONAN_CXXFLAGS ${SILKWORM_SANITIZE_COMPILER_OPTIONS})

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND CONAN_CXXFLAGS "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
  endif()

  list(JOIN CONAN_CXXFLAGS "\",\"" CONAN_CXXFLAGS_STR)
  set(CONAN_CXXFLAGS_STR "[\"${CONAN_CXXFLAGS_STR}\"]")
  set(CONAN_CXXFLAGS_ARG "tools.build:cxxflags=${CONAN_CXXFLAGS_STR}")

  list(APPEND CONAN_OPTIONS "boost:zlib=False")

  # libraries that needs to be rebuilt with sanitize flags
  # cmake-format: off
  list(APPEND CONAN_BUILD
      abseil
      boost
      grpc
      libtorrent
      protobuf
  )
  # cmake-format: on
endif()

if(SILKWORM_USE_MIMALLOC)
  # mimalloc override option causes a crash on macOS at startup in rpcdaemon, so we enable it just on Linux. mimalloc
  # should not be used in sanitizer builds or at least its override option must be disabled
  # (https://github.com/microsoft/mimalloc/issues/317#issuecomment-708506405)
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND NOT SILKWORM_SANITIZE)
    list(APPEND CONAN_OPTIONS "mimalloc:override=True")
  endif()
endif()

set(CONAN_INSTALL_ARGS
    --output-folder "${CONAN_BINARY_DIR}"
    # https://github.com/conan-io/cmake-conan/issues/607
    --settings:all "&:build_type=${CMAKE_BUILD_TYPE}"
)

foreach(VALUE IN LISTS CONAN_BUILD)
  list(APPEND CONAN_INSTALL_ARGS --build=${VALUE})
endforeach()

foreach(VALUE IN LISTS CONAN_OPTIONS)
  list(APPEND CONAN_INSTALL_ARGS --options:all=${VALUE})
endforeach()

if(CONAN_CXXFLAGS_ARG)
  list(APPEND CONAN_INSTALL_ARGS --conf:all=${CONAN_CXXFLAGS_ARG})
endif()

set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${CMAKE_SOURCE_DIR}/third_party/cmake-conan/conan_provider.cmake")
