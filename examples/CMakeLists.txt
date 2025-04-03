# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

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
