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

conan_cmake_install(
  PATH_OR_REFERENCE "${CONAN_BINARY_DIR}"
  INSTALL_FOLDER "${CONAN_BINARY_DIR}"
  BUILD missing
  PROFILE "${CMAKE_SOURCE_DIR}/cmake/profiles/${CONAN_PROFILE}" OPTIONS "${CMAKE_CONAN_OPTIONS}"
)
