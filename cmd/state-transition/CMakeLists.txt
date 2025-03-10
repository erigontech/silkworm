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

if(MSVC)
  add_link_options(/STACK:${SILKWORM_STACK_SIZE})
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
  add_link_options(-Wl,-stack_size -Wl,${SILKWORM_STACK_SIZE})
else()
  add_link_options(-Wl,-z,stack-size=${SILKWORM_STACK_SIZE})
endif()

find_package(absl REQUIRED)
find_package(CLI11 REQUIRED)
find_package(nlohmann_json REQUIRED)

add_executable(state_transition state_transition.cpp expected_state.cpp state_transition.hpp runner.cpp)
target_link_libraries(
  state_transition
  PRIVATE CLI11::CLI11
          absl::time
          ethash::keccak
          nlohmann_json::nlohmann_json
          silkworm_core
          silkworm_sentry
)

configure_file(state_transition_sample1.json ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample1.json COPYONLY)
configure_file(state_transition_sample2.json ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample2.json COPYONLY)
configure_file(state_transition_sample3.json ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample3.json COPYONLY)
configure_file(state_transition_sample4.json ${CMAKE_CURRENT_BINARY_DIR}/state_transition_sample4.json COPYONLY)
