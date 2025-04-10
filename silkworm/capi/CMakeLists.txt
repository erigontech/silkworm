# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

add_subdirectory(common)

set(TARGET silkworm_capi)

find_package(Microsoft.GSL REQUIRED)

set(PUBLIC_LIBS "")
set(PRIVATE_LIBS
    glaze::glaze
    Microsoft.GSL::GSL
    silkworm_capi_common
    silkworm_core
    silkworm_db
    silkworm_execution
    silkworm_sentry
    silkworm_rpcdaemon
)

# cmake-format: off
silkworm_library(
  ${TARGET}
  PUBLIC ${PUBLIC_LIBS}
  PRIVATE ${PRIVATE_LIBS}
  TYPE SHARED
  NO_TEST
)
# cmake-format: on

# cmake-format: off
# unit tests and cmd will use a static library version
# to avoid ODR violations when identical symbols are mixed into both .dll and .exe
silkworm_library(
  ${TARGET}_static
  PUBLIC ${PUBLIC_LIBS}
  PRIVATE ${PRIVATE_LIBS}
  TYPE STATIC
)
# cmake-format: on

# Remove custom stack_size linker option for this target
get_target_property(LINK_OPTIONS ${TARGET} LINK_OPTIONS)
list(REMOVE_ITEM LINK_OPTIONS "-Wl,-stack_size")
list(REMOVE_ITEM LINK_OPTIONS "-Wl,${SILKWORM_STACK_SIZE}")
set_target_properties(${TARGET} PROPERTIES LINK_OPTIONS "${LINK_OPTIONS}")

add_subdirectory(cli)

target_link_libraries(silkworm_capi_static_test PRIVATE silkworm_db_test_util)

# collect all public C headers into the same directory
set(HEADERS_INSTALL_PATH "${CMAKE_CURRENT_BINARY_DIR}/include")
file(GLOB_RECURSE HEADERS "../capi/*.h" "../*/capi/*.h")
add_custom_command(
  TARGET ${TARGET}
  POST_BUILD
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${HEADERS_INSTALL_PATH}"
  COMMAND ${CMAKE_COMMAND} ARGS -E copy_if_different ${HEADERS} "${HEADERS_INSTALL_PATH}"
)
