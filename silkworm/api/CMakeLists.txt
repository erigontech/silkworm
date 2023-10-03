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
  SILKWORM_API_SRC
  CONFIGURE_DEPENDS
  "*.cpp"
  "*.hpp"
  "*.c"
  "*.h"
)
list(FILTER SILKWORM_API_SRC EXCLUDE REGEX "_test\\.cpp$")
list(FILTER SILKWORM_API_SRC EXCLUDE REGEX "_benchmark\\.cpp$")

add_library(silkworm_api SHARED ${SILKWORM_API_SRC})
target_include_directories(silkworm_api PUBLIC ${SILKWORM_MAIN_DIR})

# Remove custom stack_size linker option for this target
get_target_property(silkworm_api_LINK_OPTIONS silkworm_api LINK_OPTIONS)
list(REMOVE_ITEM silkworm_api_LINK_OPTIONS "-Wl,-stack_size")
list(REMOVE_ITEM silkworm_api_LINK_OPTIONS "-Wl,${SILKWORM_STACK_SIZE}")
set_target_properties(silkworm_api PROPERTIES LINK_OPTIONS "${silkworm_api_LINK_OPTIONS}")

set(SILKWORM_API_PUBLIC_LIBS "")
set(SILKWORM_API_PRIVATE_LIBS glaze::glaze Microsoft.GSL::GSL silkworm_core silkworm_infra silkworm_node silkrpc)

target_link_libraries(
  silkworm_api
  PUBLIC ${SILKWORM_API_PUBLIC_LIBS}
  PRIVATE ${SILKWORM_API_PRIVATE_LIBS}
)
