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

# Find Protobuf installation
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
find_program(PROTOBUF_PROTOC protoc REQUIRED)

# Find gRPC installation
find_package(gRPC CONFIG REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

set(PROTO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/proto")

set(PROTOC_ARGS
    --cpp_out "${CMAKE_CURRENT_SOURCE_DIR}"
    -I "${PROTO_PATH}"
    --experimental_allow_proto3_optional
)
set(PROTOC_ARGS_GRPC
    ${PROTOC_ARGS}
    --grpc_out "${CMAKE_CURRENT_SOURCE_DIR}"
    "--plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}"
)

# ---------------------------------------------------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(TYPES_PROTO "${PROTO_PATH}/types/types.proto")

# Generate sources
set(TYPES_PROTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/types/types.pb.cc")
set(TYPES_PROTO_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/types/types.pb.h")

add_custom_command(
    OUTPUT "${TYPES_PROTO_SOURCES}" "${TYPES_PROTO_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS} "${TYPES_PROTO}"
    DEPENDS "${TYPES_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# Sentry
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(SENTRY_PROTO "${PROTO_PATH}/p2psentry/sentry.proto")

# Generate sources
set(SENTRY_PROTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.pb.cc")
set(SENTRY_PROTO_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.pb.h")
set(SENTRY_GRPC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.grpc.pb.cc")
set(SENTRY_GRPC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.grpc.pb.h")

add_custom_command(
    OUTPUT "${SENTRY_PROTO_SOURCES}" "${SENTRY_PROTO_HEADERS}" "${SENTRY_GRPC_SOURCES}" "${SENTRY_GRPC_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS_GRPC} "${SENTRY_PROTO}"
    DEPENDS "${SENTRY_PROTO}"
)

add_custom_target(generate_types_proto DEPENDS "${TYPES_PROTO_SOURCES}" "${TYPES_PROTO_HEADERS}")

add_custom_target(
    generate_sentry_grpc
    DEPENDS "${SENTRY_PROTO_SOURCES}" "${SENTRY_PROTO_HEADERS}" "${SENTRY_GRPC_SOURCES}" "${SENTRY_GRPC_HEADERS}"
            generate_types_proto
)

# ---------------------------------------------------------------------------------------------------------------------
# KV
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(KV_PROTO "${PROTO_PATH}/remote/kv.proto")

# Generate sources
set(KV_PROTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/remote/kv.pb.cc")
set(KV_PROTO_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/remote/kv.pb.h")
set(KV_GRPC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/remote/kv.grpc.pb.cc")
set(KV_GRPC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/remote/kv.grpc.pb.h")

add_custom_command(
    OUTPUT "${KV_PROTO_SOURCES}" "${KV_PROTO_HEADERS}" "${KV_GRPC_SOURCES}" "${KV_GRPC_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS_GRPC} "${KV_PROTO}"
    DEPENDS "${KV_PROTO}"
    COMMENT "Running C++ gRPC compiler on ${KV_PROTO}"
)

add_custom_target(
    generate_kv_grpc
    DEPENDS "${KV_PROTO_SOURCES}" "${KV_PROTO_HEADERS}" "${KV_GRPC_SOURCES}" "${KV_GRPC_HEADERS}"
            generate_types_proto
)

# ---------------------------------------------------------------------------------------------------------------------
# ETHBACKEND
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(ETHBACKEND_PROTO "${PROTO_PATH}/remote/ethbackend.proto")

# Generate sources
set(ETHBACKEND_PROTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/remote/ethbackend.pb.cc")
set(ETHBACKEND_PROTO_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/remote/ethbackend.pb.h")
set(ETHBACKEND_GRPC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/remote/ethbackend.grpc.pb.cc")
set(ETHBACKEND_GRPC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/remote/ethbackend.grpc.pb.h")

add_custom_command(
    OUTPUT "${ETHBACKEND_PROTO_SOURCES}" "${ETHBACKEND_PROTO_HEADERS}" "${ETHBACKEND_GRPC_SOURCES}" "${ETHBACKEND_GRPC_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS_GRPC} "${ETHBACKEND_PROTO}"
    DEPENDS "${ETHBACKEND_PROTO}"
    COMMENT "Running C++ gRPC compiler on ${ETHBACKEND_PROTO}"
)

add_custom_target(
    generate_ethbackend_grpc
    DEPENDS "${ETHBACKEND_PROTO_SOURCES}" "${ETHBACKEND_PROTO_HEADERS}" "${ETHBACKEND_GRPC_SOURCES}" "${ETHBACKEND_GRPC_HEADERS}"
            generate_types_proto
)
