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

find_package(Boost REQUIRED COMPONENTS headers)

# Target 'execute' is used to exercise the Silkworm C API library even if using C++ main
add_executable(execute execute.cpp)

set(PRIVATE_LIBS
    Boost::headers
    silkworm_infra
    silkworm_db
    silkworm_rpcdaemon
    silkworm_capi_static
    silkworm_infra_cli
)

target_link_libraries(execute PRIVATE ${PRIVATE_LIBS})

# Target 'capi_main' is used to check that Silkworm C API header passes pure C compilation (avoid this target in
# sanitizer build due to linking errors w/ libFuzzingEngine dependencies)
if(NOT SILKWORM_SANITIZE)
  add_executable(capi_main main.c)
  target_link_libraries(capi_main PRIVATE silkworm_capi)
endif()
