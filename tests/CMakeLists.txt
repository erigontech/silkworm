#[[
   Copyright 2020 The Silkworm Authors

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

hunter_add_package(Boost)
find_package(Boost CONFIG REQUIRED)

hunter_add_package(Catch)
find_package(Catch2 CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_TESTS CONFIGURE_DEPENDS "../src/*_test.cpp")

add_executable(tests main.cpp ${SILKWORM_TESTS})

target_link_libraries(tests PRIVATE Catch2::Catch2 silkworm_eth Boost::boost)
