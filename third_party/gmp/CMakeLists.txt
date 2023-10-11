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
  add_custom_target(gmplib DEPENDS gmp::GMP)

  # derive the path variables from the package for intx, libff
  get_target_property(GMP_INCLUDE_DIR gmp::GMP INTERFACE_INCLUDE_DIRECTORIES)
  set(GMP_INCLUDE_DIR
      "${GMP_INCLUDE_DIR}"
      CACHE PATH ""
  )
  get_target_property(GMP_LIBRARY_DIR gmp::GMP INTERFACE_LINK_DIRECTORIES)
  find_library(GMP_LIBRARY gmp "${GMP_LIBRARY_DIR}")
endif()
