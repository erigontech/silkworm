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

find_package(Microsoft.GSL REQUIRED)

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

set(TARGET silkworm_capi)
add_library(${TARGET} SHARED ${SRC})
target_include_directories(${TARGET} PUBLIC ${SILKWORM_MAIN_DIR})

# Remove custom stack_size linker option for this target
get_target_property(LINK_OPTIONS ${TARGET} LINK_OPTIONS)
list(REMOVE_ITEM LINK_OPTIONS "-Wl,-stack_size")
list(REMOVE_ITEM LINK_OPTIONS "-Wl,${SILKWORM_STACK_SIZE}")
set_target_properties(${TARGET} PROPERTIES LINK_OPTIONS "${LINK_OPTIONS}")

set(PUBLIC_LIBS "")
set(PRIVATE_LIBS
    glaze::glaze
    Microsoft.GSL::GSL
    silkworm_core
    silkworm_infra
    silkworm_node
    silkworm_sentry
    silkworm_rpcdaemon
)

target_link_libraries(
  ${TARGET}
  PUBLIC ${PUBLIC_LIBS}
  PRIVATE ${PRIVATE_LIBS}
)
