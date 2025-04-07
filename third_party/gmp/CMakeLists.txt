# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

function(expand_config_gen_expr expr build_type var)
  string(REGEX MATCH "<CONFIG:${build_type}>:[^>]+" VALUE "${expr}")
  string(REPLACE "<CONFIG:${build_type}>:" "" VALUE "${VALUE}")
  set(${var}
      "${VALUE}"
      PARENT_SCOPE
  )
endfunction()

if(GMP_LIBRARY STREQUAL "GMP_LIBRARY-NOTFOUND")
  unset(GMP_LIBRARY CACHE)
  unset(GMP_INCLUDE_DIR CACHE)
endif()

if(DEFINED GMP_LIBRARY)
  add_library(gmplib STATIC IMPORTED)
  set_target_properties(gmplib PROPERTIES IMPORTED_LOCATION "${GMP_LIBRARY}")
  if(DEFINED GMP_INCLUDE_DIR)
    set_target_properties(gmplib PROPERTIES INTERFACE_INCLUDE_DIRECTORIES "${GMP_INCLUDE_DIR}")
  else()
    message(FATAL_ERROR "GMP_INCLUDE_DIR is required if a custom GMP_LIBRARY is provided")
  endif()
else()
  find_package(gmp REQUIRED)
  add_custom_target(gmplib DEPENDS gmp::gmp)

  # derive the path variables from the package for intx, libff
  get_target_property(GMP_INCLUDE_DIR_EXPR gmp::libgmp INTERFACE_INCLUDE_DIRECTORIES)
  expand_config_gen_expr("${GMP_INCLUDE_DIR_EXPR}" ${CMAKE_BUILD_TYPE} GMP_INCLUDE_DIR)
  set(GMP_INCLUDE_DIR
      "${GMP_INCLUDE_DIR}"
      CACHE PATH ""
  )
  get_target_property(GMP_LIBRARY_DIR_EXPR gmp::libgmp INTERFACE_LINK_DIRECTORIES)
  expand_config_gen_expr("${GMP_LIBRARY_DIR_EXPR}" ${CMAKE_BUILD_TYPE} GMP_LIBRARY_DIR)
  find_library(
    GMP_LIBRARY gmp
    PATHS "${GMP_LIBRARY_DIR}" REQUIRED
    NO_DEFAULT_PATH
  )
endif()
