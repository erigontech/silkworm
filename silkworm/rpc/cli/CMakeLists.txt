# Copyright 2025 The Silkworm Authors
# SPDX-License-Identifier: Apache-2.0

find_package(absl REQUIRED)
find_package(gRPC REQUIRED)
find_package(Protobuf REQUIRED)

add_library(silkworm_rpcdaemon_cli "rpcdaemon_options.cpp")
target_link_libraries(silkworm_rpcdaemon_cli PUBLIC silkworm_rpcdaemon silkworm_infra_cli)

add_executable(grpc_toolbox "grpc_toolbox.cpp")
target_link_libraries(grpc_toolbox absl::flags_parse gRPC::grpc++ protobuf::libprotobuf silkworm_rpcdaemon)
