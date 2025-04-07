# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

# https://stackoverflow.com/a/62311397/1009546

function(get_all_targets var)
  set(targets)
  get_all_targets_recursive(targets ${CMAKE_CURRENT_SOURCE_DIR})
  set(${var}
      ${targets}
      PARENT_SCOPE
  )
endfunction()

macro(get_all_targets_recursive targets dir)
  get_property(
    subdirectories
    DIRECTORY ${dir}
    PROPERTY SUBDIRECTORIES
  )
  foreach(subdir ${subdirectories})
    get_all_targets_recursive(${targets} ${subdir})
  endforeach()

  get_property(
    current_targets
    DIRECTORY ${dir}
    PROPERTY BUILDSYSTEM_TARGETS
  )
  list(APPEND ${targets} ${current_targets})
endmacro()
