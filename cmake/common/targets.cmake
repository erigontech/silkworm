# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(Catch2 REQUIRED)

macro(list_filter_dirs VAR DIRS)
  foreach(DIR IN LISTS ${DIRS})
    list(FILTER ${VAR} EXCLUDE REGEX "^${DIR}/")
  endforeach()
endmacro()

function(silkworm_library TARGET)
  cmake_parse_arguments(
    PARSE_ARGV
    1
    "ARG"
    "NO_TEST"
    "TYPE"
    "PUBLIC;PRIVATE"
  )

  file(
    GLOB_RECURSE
    SRC
    CONFIGURE_DEPENDS
    "*.cpp"
    "*.hpp"
    "*.c"
    "*.h"
  )

  # remove subdirectories with CMakeLists.txt
  get_directory_property(SUB_LIBS SUBDIRECTORIES)
  list_filter_dirs(SRC SUB_LIBS)

  # cli subdirectories with CMakeLists.txt belong only to silkworm_*_cli libraries
  if(NOT "${CMAKE_CURRENT_SOURCE_DIR}" MATCHES "/cli$")
    list(FILTER SRC EXCLUDE REGEX "\/cli\/")
  endif()

  set(TEST_REGEX "_test\\.cpp$")
  # test_util subdirectories without CMakeLists.txt belong to TEST_SRC
  if(NOT "${CMAKE_CURRENT_SOURCE_DIR}" MATCHES "/test_util$")
    set(TEST_REGEX "(${TEST_REGEX}|\/test_util\/)")
  endif()

  set(TEST_SRC ${SRC})
  list(FILTER TEST_SRC INCLUDE REGEX "${TEST_REGEX}")

  list(FILTER SRC EXCLUDE REGEX "${TEST_REGEX}")
  list(FILTER SRC EXCLUDE REGEX "_benchmark\\.cpp$")

  add_library(${TARGET} ${ARG_TYPE} ${SRC})

  target_include_directories(${TARGET} PUBLIC "${SILKWORM_MAIN_DIR}")
  target_link_libraries(
    ${TARGET}
    PUBLIC "${ARG_PUBLIC}"
    PRIVATE "${ARG_PRIVATE}"
  )

  # unit tests
  if(TEST_SRC AND NOT ${ARG_NO_TEST})
    set(TEST_TARGET ${TARGET}_test)
    add_executable(${TEST_TARGET} ${TEST_SRC})
    target_link_libraries(${TEST_TARGET} PRIVATE Catch2::Catch2WithMain ${TARGET})
  endif()
endfunction()
