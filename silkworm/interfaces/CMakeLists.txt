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
find_package(Protobuf REQUIRED)

if(CONAN_PACKAGE_MANAGER)
  find_program(PROTOBUF_PROTOC protoc)
  if(NOT PROTOBUF_PROTOC)
    find_program(PROTOBUF_PROTOC ${PROTOC_PROGRAM} REQUIRED)
  endif()
else()
  find_program(PROTOBUF_PROTOC protoc REQUIRED)
endif()

# Find Protobuf version
execute_process(
    COMMAND "${PROTOBUF_PROTOC}" --version
    OUTPUT_VARIABLE PROTOC_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
string(SUBSTRING "${PROTOC_VERSION}" 10 -1 PROTOC_VERSION)

# Find gRPC installation
find_package(gRPC REQUIRED)

if(CONAN_PACKAGE_MANAGER)
  find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin)
  if(NOT GRPC_CPP_PLUGIN_EXECUTABLE)
    find_program(GRPC_CPP_PLUGIN_EXECUTABLE NAMES grpc_cpp_plugin PATHS "${gRPC_INCLUDE_DIRS}/../bin/" NO_DEFAULT_PATH REQUIRED)
  endif()
else()
  find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)
endif()

set(PROTO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(OUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOC_VERSION}")
set(OUT_PATH_SYMLINK "${CMAKE_CURRENT_SOURCE_DIR}")

set(PROTOC_ARGS
    --cpp_out "${OUT_PATH}"
    -I "${PROTO_PATH}"
    --experimental_allow_proto3_optional
)
set(PROTOC_ARGS_GRPC
    ${PROTOC_ARGS}
    --grpc_out "${OUT_PATH}"
    "--plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}"
)

macro(create_symlink_target target link_path target_path)
    add_custom_command(
        OUTPUT "${link_path}"
        COMMAND "${CMAKE_COMMAND}"
        ARGS -E create_symlink "${target_path}" "${link_path}"
        COMMENT "${target}: symlink ${link_path} -> ${target_path}")
    add_custom_target(${target} DEPENDS "${link_path}")
endmacro()

# ---------------------------------------------------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(TYPES_PROTO "${PROTO_PATH}/types/types.proto")

# Generate sources
set(TYPES_PROTO_SOURCES "${OUT_PATH}/types/types.pb.cc")
set(TYPES_PROTO_HEADERS "${OUT_PATH}/types/types.pb.h")

add_custom_command(
    OUTPUT "${TYPES_PROTO_SOURCES}" "${TYPES_PROTO_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS} "${TYPES_PROTO}"
    DEPENDS "${TYPES_PROTO}"
    COMMENT "Running C++ gRPC compiler on ${TYPES_PROTO}"
)

create_symlink_target(generate_types_proto_symlink "${OUT_PATH_SYMLINK}/types" "${OUT_PATH}/types")

add_custom_target(
    generate_types_proto
    DEPENDS "${TYPES_PROTO_SOURCES}" "${TYPES_PROTO_HEADERS}"
            generate_types_proto_symlink
)

# ---------------------------------------------------------------------------------------------------------------------
# Sentry
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(SENTRY_PROTO "${PROTO_PATH}/p2psentry/sentry.proto")

# Generate sources
set(SENTRY_PROTO_SOURCES "${OUT_PATH}/p2psentry/sentry.pb.cc")
set(SENTRY_PROTO_HEADERS "${OUT_PATH}/p2psentry/sentry.pb.h")
set(SENTRY_GRPC_SOURCES "${OUT_PATH}/p2psentry/sentry.grpc.pb.cc")
set(SENTRY_GRPC_HEADERS "${OUT_PATH}/p2psentry/sentry.grpc.pb.h")

add_custom_command(
    OUTPUT "${SENTRY_PROTO_SOURCES}" "${SENTRY_PROTO_HEADERS}" "${SENTRY_GRPC_SOURCES}" "${SENTRY_GRPC_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS_GRPC} "${SENTRY_PROTO}"
    DEPENDS "${SENTRY_PROTO}"
    COMMENT "Running C++ gRPC compiler on ${SENTRY_PROTO}"
)

create_symlink_target(generate_sentry_grpc_symlink "${OUT_PATH_SYMLINK}/p2psentry" "${OUT_PATH}/p2psentry")

add_custom_target(
    generate_sentry_grpc
    DEPENDS "${SENTRY_PROTO_SOURCES}" "${SENTRY_PROTO_HEADERS}" "${SENTRY_GRPC_SOURCES}" "${SENTRY_GRPC_HEADERS}"
            generate_types_proto
            generate_sentry_grpc_symlink
)

# ---------------------------------------------------------------------------------------------------------------------
# KV
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(KV_PROTO "${PROTO_PATH}/remote/kv.proto")

# Generate sources
set(KV_PROTO_SOURCES "${OUT_PATH}/remote/kv.pb.cc")
set(KV_PROTO_HEADERS "${OUT_PATH}/remote/kv.pb.h")
set(KV_GRPC_SOURCES "${OUT_PATH}/remote/kv.grpc.pb.cc")
set(KV_GRPC_HEADERS "${OUT_PATH}/remote/kv.grpc.pb.h")

add_custom_command(
    OUTPUT "${KV_PROTO_SOURCES}" "${KV_PROTO_HEADERS}" "${KV_GRPC_SOURCES}" "${KV_GRPC_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS ${PROTOC_ARGS_GRPC} "${KV_PROTO}"
    DEPENDS "${KV_PROTO}"
    COMMENT "Running C++ gRPC compiler on ${KV_PROTO}"
)

create_symlink_target(generate_remote_grpc_symlink "${OUT_PATH_SYMLINK}/remote" "${OUT_PATH}/remote")

add_custom_target(
    generate_kv_grpc
    DEPENDS "${KV_PROTO_SOURCES}" "${KV_PROTO_HEADERS}" "${KV_GRPC_SOURCES}" "${KV_GRPC_HEADERS}"
            generate_types_proto
            generate_remote_grpc_symlink
)

# ---------------------------------------------------------------------------------------------------------------------
# ETHBACKEND
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(ETHBACKEND_PROTO "${PROTO_PATH}/remote/ethbackend.proto")

# Generate sources
set(ETHBACKEND_PROTO_SOURCES "${OUT_PATH}/remote/ethbackend.pb.cc")
set(ETHBACKEND_PROTO_HEADERS "${OUT_PATH}/remote/ethbackend.pb.h")
set(ETHBACKEND_GRPC_SOURCES "${OUT_PATH}/remote/ethbackend.grpc.pb.cc")
set(ETHBACKEND_GRPC_HEADERS "${OUT_PATH}/remote/ethbackend.grpc.pb.h")

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
            generate_remote_grpc_symlink
)
