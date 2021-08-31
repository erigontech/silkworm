#[[
   Copyright 2021 The Silkworm Authors

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

find_package(benchmark CONFIG REQUIRED)

add_executable(buffer buffer.cpp)
target_link_libraries(buffer PRIVATE silkworm_node)
  
add_executable(precompile precompile.cpp)
target_link_libraries(precompile silkworm_core benchmark::benchmark)
