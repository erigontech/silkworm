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

set(CONAN_BINARY_DIR "${CMAKE_BINARY_DIR}/conan")
list(APPEND CMAKE_MODULE_PATH ${CONAN_BINARY_DIR})
list(APPEND CMAKE_PREFIX_PATH ${CONAN_BINARY_DIR})

# disable verbose logging from FindXXX.cmake files
set(CONAN_CMAKE_SILENT_OUTPUT ON)

include("${CMAKE_SOURCE_DIR}/third_party/cmake-conan/conan.cmake")

# provide a static conanfile.py instead of generating it with conan_cmake_configure()
file(COPY "${CMAKE_SOURCE_DIR}/conanfile.py" DESTINATION "${CONAN_BINARY_DIR}")

if(NOT DEFINED CONAN_PROFILE)
  guess_conan_profile()
endif()
message(STATUS "CONAN_PROFILE: ${CONAN_PROFILE}")

set(CONAN_BUILD "missing")
set(CONAN_CXXFLAGS_ARG)
set(CONAN_OPTIONS)

if(SILKWORM_SANITIZE_COMPILER_OPTIONS)
  set(CONAN_CXXFLAGS ${SILKWORM_SANITIZE_COMPILER_OPTIONS})

  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    list(APPEND CONAN_CXXFLAGS "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
  endif()

  list(JOIN CONAN_CXXFLAGS "\", \"" CONAN_CXXFLAGS_STR)
  set(CONAN_CXXFLAGS_STR "[\"${CONAN_CXXFLAGS_STR}\"]")
  set(CONAN_CXXFLAGS_ARG "tools.build:cxxflags=${CONAN_CXXFLAGS_STR}")

  list(APPEND CONAN_OPTIONS "boost:zlib=False")

  # libraries that needs to be rebuilt with sanitize flags
  # cmake-format: off
  set(CONAN_BUILD
      abseil
      boost
      grpc
      protobuf
  )
  # cmake-format: on
endif()

if(SILKWORM_USE_MIMALLOC)
  # Do not use mimalloc override on sanitizer builds (https://github.com/microsoft/mimalloc/issues/317#issuecomment-708506405)
  # Moreover, mimalloc override causes a crash on macOS at startup in rpcdaemon, so we just enable it on Linux
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND NOT SILKWORM_SANITIZE)
    list(APPEND CONAN_OPTIONS "mimalloc:override=True")
  endif()
endif()

conan_cmake_install(
  PATH_OR_REFERENCE "${CONAN_BINARY_DIR}"
  INSTALL_FOLDER "${CONAN_BINARY_DIR}"
  BUILD ${CONAN_BUILD}
  OPTIONS ${CONAN_OPTIONS}
  PROFILE "${CMAKE_SOURCE_DIR}/cmake/profiles/${CONAN_PROFILE}"
  CONF "${CONAN_CXXFLAGS_ARG}"
)
