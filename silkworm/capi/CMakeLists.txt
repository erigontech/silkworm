# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

include("${SILKWORM_MAIN_DIR}/cmake/common/targets.cmake")

set(TARGET silkworm_capi)

find_package(Microsoft.GSL REQUIRED)

set(PUBLIC_LIBS "")
set(PRIVATE_LIBS
    glaze::glaze
    Microsoft.GSL::GSL
    silkworm_core
    silkworm_db
    silkworm_sentry
    silkworm_node
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

target_link_libraries(silkworm_capi_static_test PRIVATE silkworm_db_test_util silkworm_node)
