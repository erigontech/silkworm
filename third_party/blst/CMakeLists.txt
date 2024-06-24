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

include(ExternalProject)

set(BLST_DIR ${CMAKE_CURRENT_SOURCE_DIR}/blst)
if(SILKWORM_WASM_API)
  set(BLST_BUILD_SCRIPT ./build.sh CC=/opt/wasi-sdk/bin/clang -D__BLST_PORTABLE__)
  set(BLST_LIB libblst.a)
elseif(MSVC)
  set(BLST_BUILD_SCRIPT build.bat)
  set(BLST_LIB blst.lib)
else()
  set(BLST_BUILD_SCRIPT_ARGS "")
  if(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    set(BLST_BUILD_SCRIPT_ARGS "-mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
  endif()
  set(BLST_BUILD_SCRIPT ./build.sh ${BLST_BUILD_SCRIPT_ARGS})
  set(BLST_LIB libblst.a)
endif()

ExternalProject_Add(
  blst_build
  SOURCE_DIR ${BLST_DIR}
  CONFIGURE_COMMAND ""
  BUILD_COMMAND ${BLST_BUILD_SCRIPT}
  BUILD_IN_SOURCE 1
  BUILD_BYPRODUCTS ${BLST_DIR}/${BLST_LIB}
  LOG_BUILD YES
  LOG_OUTPUT_ON_FAILURE YES
  INSTALL_COMMAND ""
)

add_library(blst STATIC IMPORTED GLOBAL)
add_dependencies(blst blst_build)
# cmake-format: off
set_target_properties(
  blst
  PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${BLST_DIR}/bindings
             IMPORTED_LOCATION ${BLST_DIR}/${BLST_LIB}
)
# cmake-format: on
