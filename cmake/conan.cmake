# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include(${CMAKE_CURRENT_LIST_DIR}/compiler_settings_sanitize.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/conan_quiet.cmake)

function(guess_conan_profile)
  if("${CMAKE_HOST_SYSTEM_PROCESSOR}" STREQUAL "" AND CMAKE_HOST_UNIX)
    execute_process(
      COMMAND uname -m
      OUTPUT_VARIABLE CMAKE_HOST_SYSTEM_PROCESSOR
      OUTPUT_STRIP_TRAILING_WHITESPACE
      COMMAND_ERROR_IS_FATAL ANY
    )
  endif()

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
    set(PROFILE windows_msvc_193_release)
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

macro(format_list_as_json_array list_var var)
  list(JOIN ${list_var} "\",\"" ${var})
  set(${var} "[\"${${var}}\"]")
endmacro()

# unset(CONAN_COMMAND CACHE)
find_program(
  CONAN_COMMAND "conan"
  PATHS /opt/conan2/bin /opt/homebrew/opt/conan@2/bin
  NO_DEFAULT_PATH
)
if(NOT CONAN_COMMAND)
  find_program(CONAN_COMMAND "conan" PATHS ~/.local/bin REQUIRED)
endif()

# use "verbose" for more detailed conan install logs
set(CONAN_VERBOSITY "error")
set(CONAN_BINARY_DIR "${CMAKE_BINARY_DIR}/conan2")

if(NOT DEFINED CONAN_PROFILE)
  guess_conan_profile()
endif()
message(VERBOSE "CONAN_PROFILE: ${CONAN_PROFILE}")
set(CONAN_PROFILE_PATH "${CMAKE_SOURCE_DIR}/cmake/profiles/${CONAN_PROFILE}")
set(CONAN_HOST_PROFILE "${CONAN_PROFILE_PATH}")
set(CONAN_BUILD_PROFILE "${CONAN_PROFILE_PATH}")
get_conan_build_type("${CONAN_PROFILE_PATH}" CONAN_BUILD_TYPE)

set(CONAN_BUILD "missing")
set(CONAN_SETTINGS "")
set(CONAN_OPTIONS "")
set(CONAN_CONF "")

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Darwin")
  set(OS_VERSION_MIN_CXXFLAG "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()

if(OS_VERSION_MIN_CXXFLAG AND NOT SILKWORM_SANITIZE_COMPILER_OPTIONS)
  list(APPEND CONAN_CONF "tools.build:cxxflags=[\"${OS_VERSION_MIN_CXXFLAG}\"]")
  list(APPEND CONAN_CONF "tools.build:cflags=[\"${OS_VERSION_MIN_CXXFLAG}\"]")
endif()

if(SILKWORM_SANITIZE_COMPILER_OPTIONS)
  set(CONAN_CXXFLAGS ${SILKWORM_SANITIZE_COMPILER_OPTIONS})

  if(OS_VERSION_MIN_CXXFLAG)
    list(APPEND CONAN_CXXFLAGS ${OS_VERSION_MIN_CXXFLAG})
    list(APPEND CONAN_CONF "tools.build:cflags=[\"${OS_VERSION_MIN_CXXFLAG}\"]")
  endif()

  format_list_as_json_array(CONAN_CXXFLAGS CONAN_CXXFLAGS_STR)
  list(APPEND CONAN_CONF "tools.build:cxxflags=${CONAN_CXXFLAGS_STR}")

  list(APPEND CONAN_OPTIONS "boost/*:zlib=False")
  list(APPEND CONAN_OPTIONS "grpc/*:with_libsystemd=False")

  # libraries that must be rebuilt with sanitizer flags
  # cmake-format: off
  set(CONAN_BUILD
      "abseil/*"
      "boost/*"
      "grpc/*"
      "libtorrent/*"
      "protobuf/*"
  )
  list(APPEND CONAN_BUILD "missing")
  # cmake-format: on
endif()

if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Windows")
  set(CONAN_VERBOSITY "verbose")
  # make sure to not rebuild anything from source unless required
  set(CONAN_BUILD "missing:libtorrent/*")
  list(APPEND CONAN_BUILD "missing:protobuf/*")
  # HACK: MSVC is "multi config" and conan_provider.cmake runs 2 conan install commands for both Release and Debug
  # despite CMAKE_BUILD_TYPE. This adds an extra build_type setting to both commands to override and force the desired
  # build type. It still runs 2 commands, but the 2nd one has no effect.
  list(APPEND CONAN_SETTINGS "build_type=${CMAKE_BUILD_TYPE}")
  # most Windows packages on ConanCenter are built for cppstd=14, but some packages require at least cppstd=17
  # (otherwise report "Invalid" status)
  list(APPEND CONAN_SETTINGS "magic_enum/*:compiler.cppstd=17")
  list(APPEND CONAN_SETTINGS "tomlplusplus/*:compiler.cppstd=17")
endif()

if(SILKWORM_USE_MIMALLOC)
  # mimalloc override option causes a crash on macOS at startup in rpcdaemon, so we enable it just on Linux. mimalloc
  # should not be used in sanitizer builds or at least its override option must be disabled
  # (https://github.com/microsoft/mimalloc/issues/317#issuecomment-708506405)
  if(CMAKE_HOST_SYSTEM_NAME STREQUAL "Linux" AND NOT SILKWORM_SANITIZE)
    list(APPEND CONAN_OPTIONS "mimalloc/*:override=True")
  endif()
endif()

if(SILKWORM_CORE_ONLY)
  list(APPEND CONAN_CONF "catch2/*:tools.build:cxxflags=[\"-fno-exceptions\"]")
endif()

# cmake-format: off
set(CONAN_INSTALL_ARGS
    -v ${CONAN_VERBOSITY}
    --output-folder "${CONAN_BINARY_DIR}"
    # https://github.com/conan-io/cmake-conan/issues/607
    --settings:all "&:build_type=${CMAKE_BUILD_TYPE}"
)
# cmake-format: on

foreach(VALUE IN LISTS CONAN_BUILD)
  list(APPEND CONAN_INSTALL_ARGS --build=${VALUE})
endforeach()

foreach(VALUE IN LISTS CONAN_SETTINGS)
  list(APPEND CONAN_INSTALL_ARGS --settings:all=${VALUE})
endforeach()

foreach(VALUE IN LISTS CONAN_OPTIONS)
  list(APPEND CONAN_INSTALL_ARGS --options:all=${VALUE})
endforeach()

foreach(VALUE IN LISTS CONAN_CONF)
  list(APPEND CONAN_INSTALL_ARGS --conf:all=${VALUE})
endforeach()

set(CMAKE_PROJECT_TOP_LEVEL_INCLUDES "${CMAKE_SOURCE_DIR}/third_party/cmake-conan/conan_provider.cmake")
