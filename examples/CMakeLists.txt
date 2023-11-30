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

if(NOT SILKWORM_CORE_ONLY)

  find_package(absl REQUIRED)
  find_package(gRPC REQUIRED)
  find_package(Protobuf REQUIRED)

  add_executable(get_latest_block get_latest_block.cpp)
  target_include_directories(get_latest_block PRIVATE ${CMAKE_SOURCE_DIR})
  target_link_libraries(
    get_latest_block absl::flags_parse gRPC::grpc++_unsecure protobuf::libprotobuf silkworm_rpcdaemon
  )

endif()
