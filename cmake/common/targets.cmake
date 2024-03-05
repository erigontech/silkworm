#[[
   Copyright 2023 The Silkworm Authors

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

find_package(Catch2 REQUIRED)

macro(list_filter VAR EXCLUDE_REGEX)
  foreach(R IN LISTS ${EXCLUDE_REGEX})
    list(FILTER ${VAR} EXCLUDE REGEX "${R}")
  endforeach()
endmacro()

function(silkworm_library TARGET)
  cmake_parse_arguments(
    PARSE_ARGV
    1
    "ARG"
    ""
    ""
    "PUBLIC;PRIVATE;EXCLUDE_REGEX;TYPE"
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
  list(FILTER SRC EXCLUDE REGEX "_test\\.cpp$")
  list(FILTER SRC EXCLUDE REGEX "_benchmark\\.cpp$")
  list_filter(SRC ARG_EXCLUDE_REGEX)
  add_library(${TARGET} ${ARG_TYPE} ${SRC})

  target_include_directories(${TARGET} PUBLIC "${SILKWORM_MAIN_DIR}")
  target_link_libraries(
    ${TARGET}
    PUBLIC "${ARG_PUBLIC}"
    PRIVATE "${ARG_PRIVATE}"
  )

  # unit tests
  file(GLOB_RECURSE TEST_SRC CONFIGURE_DEPENDS "*_test.cpp")
  list_filter(TEST_SRC ARG_EXCLUDE_REGEX)
  if(TEST_SRC)
    set(TEST_TARGET ${TARGET}_test)
    add_executable(${TEST_TARGET} "${SILKWORM_MAIN_DIR}/cmd/test/unit_test.cpp" ${TEST_SRC})
    get_target_property(TARGET_TYPE ${TARGET} TYPE)
    if(TARGET_TYPE STREQUAL SHARED_LIBRARY)
      target_link_libraries(
        ${TEST_TARGET}
        PRIVATE ${TARGET} "${ARG_PUBLIC}" "${ARG_PRIVATE}" Catch2::Catch2
      )
    else()
      target_link_libraries(${TEST_TARGET} PRIVATE ${TARGET} Catch2::Catch2)
    endif()
  endif()
endfunction()
