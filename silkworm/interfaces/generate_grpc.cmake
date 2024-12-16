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

find_program(
  PROTOBUF_PROTOC protoc
  PATHS "${protobuf_INCLUDE_DIR}/../bin" NO_CACHE REQUIRED
  NO_DEFAULT_PATH
)
if(NOT EXISTS "${PROTOBUF_PROTOC}")
  message(FATAL_ERROR "PROTOBUF_PROTOC not found at '${PROTOBUF_PROTOC}'")
endif()

# Find Protobuf version
execute_process(
  COMMAND "${PROTOBUF_PROTOC}" --version
  OUTPUT_VARIABLE PROTOC_VERSION
  OUTPUT_STRIP_TRAILING_WHITESPACE
  COMMAND_ERROR_IS_FATAL ANY
)
string(SUBSTRING "${PROTOC_VERSION}" 10 -1 PROTOC_VERSION)

# Find gRPC installation
find_package(gRPC REQUIRED)

set(GRPC_CPP_PLUGIN_EXECUTABLE "${GRPC_CPP_PLUGIN_PROGRAM}")
if(NOT EXISTS "${GRPC_CPP_PLUGIN_EXECUTABLE}")
  message(FATAL_ERROR "GRPC_CPP_PLUGIN_EXECUTABLE not found at '${GRPC_CPP_PLUGIN_EXECUTABLE}'")
endif()

set(PROTO_PATH "${SILKWORM_MAIN_DIR}/third_party/erigon-interfaces")
set(OUT_PATH "${CMAKE_CURRENT_SOURCE_DIR}/${PROTOC_VERSION}")
set(OUT_PATH_SYMLINK "${CMAKE_CURRENT_SOURCE_DIR}")

# cmake-format: off
set(PROTOC_ARGS
    --cpp_out "${OUT_PATH}"
    -I "${PROTO_PATH}"
    --experimental_allow_proto3_optional
)
set(PROTOC_ARGS_GRPC
    ${PROTOC_ARGS}
    --grpc_out generate_mock_code=true:"${OUT_PATH}"
    "--plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_EXECUTABLE}"
)
# cmake-format: on

macro(create_symlink_target target link_path target_path)
  add_custom_command(
    OUTPUT "${link_path}"
    COMMAND "${CMAKE_COMMAND}" ARGS -E remove_directory "${link_path}"
    COMMAND "${CMAKE_COMMAND}" ARGS -E create_symlink "${target_path}" "${link_path}"
    COMMENT "${target}: symlink ${link_path} -> ${target_path}"
  )
  add_custom_target(${target} DEPENDS "${link_path}")
endmacro()

# ---------------------------------------------------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(TYPES_PROTO "${PROTO_PATH}/types/types.proto")

set(TYPES_SOURCES_SYMLINK "${OUT_PATH_SYMLINK}/types/types.pb.cc" "${OUT_PATH_SYMLINK}/types/types.pb.h")

create_symlink_target(generate_types_proto_symlink "${OUT_PATH_SYMLINK}/types" "${OUT_PATH}/types")

add_custom_command(
  OUTPUT ${TYPES_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS} "${TYPES_PROTO}"
  DEPENDS ${TYPES_PROTO} generate_types_proto_symlink
  COMMENT "Running C++ gRPC compiler on ${TYPES_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(EXECUTION_PROTO "${PROTO_PATH}/execution/execution.proto")

# Generate sources
set(EXECUTION_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/execution/execution.grpc.pb.cc" "${OUT_PATH_SYMLINK}/execution/execution.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/execution/execution.pb.cc" "${OUT_PATH_SYMLINK}/execution/execution.pb.h"
)

create_symlink_target(generate_execution_grpc_symlink "${OUT_PATH_SYMLINK}/execution" "${OUT_PATH}/execution")

add_custom_command(
  OUTPUT ${EXECUTION_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${EXECUTION_PROTO}"
  DEPENDS ${EXECUTION_PROTO} generate_execution_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${EXECUTION_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# Sentry
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(SENTRY_PROTO "${PROTO_PATH}/p2psentry/sentry.proto")

# cmake-format: off
set(SENTRY_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/p2psentry/sentry.grpc.pb.cc"
    "${OUT_PATH_SYMLINK}/p2psentry/sentry.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/p2psentry/sentry.pb.cc"
    "${OUT_PATH_SYMLINK}/p2psentry/sentry.pb.h"
    "${OUT_PATH_SYMLINK}/p2psentry/sentry_mock.grpc.pb.h"
)
# cmake-format: on

create_symlink_target(generate_sentry_grpc_symlink "${OUT_PATH_SYMLINK}/p2psentry" "${OUT_PATH}/p2psentry")

add_custom_command(
  OUTPUT ${SENTRY_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${SENTRY_PROTO}"
  DEPENDS ${SENTRY_PROTO} generate_sentry_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${SENTRY_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# KV
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(KV_PROTO "${PROTO_PATH}/remote/kv.proto")

# cmake-format: off
set(KV_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/remote/kv.grpc.pb.cc"
    "${OUT_PATH_SYMLINK}/remote/kv.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/remote/kv.pb.cc"
    "${OUT_PATH_SYMLINK}/remote/kv.pb.h"
    "${OUT_PATH_SYMLINK}/remote/kv_mock.grpc.pb.h"
)
# cmake-format: on

create_symlink_target(generate_remote_grpc_symlink "${OUT_PATH_SYMLINK}/remote" "${OUT_PATH}/remote")

add_custom_command(
  OUTPUT ${KV_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${KV_PROTO}"
  DEPENDS ${KV_PROTO} generate_remote_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${KV_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# ETHBACKEND
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(ETHBACKEND_PROTO "${PROTO_PATH}/remote/ethbackend.proto")

# cmake-format: off
set(ETHBACKEND_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/remote/ethbackend.grpc.pb.cc"
    "${OUT_PATH_SYMLINK}/remote/ethbackend.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/remote/ethbackend.pb.cc"
    "${OUT_PATH_SYMLINK}/remote/ethbackend.pb.h"
    "${OUT_PATH_SYMLINK}/remote/ethbackend_mock.grpc.pb.h"
)
# cmake-format: on

add_custom_command(
  OUTPUT ${ETHBACKEND_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${ETHBACKEND_PROTO}"
  DEPENDS ${ETHBACKEND_PROTO} generate_remote_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${ETHBACKEND_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# BOR
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(BOR_PROTO "${PROTO_PATH}/remote/bor.proto")

# cmake-format: off
set(BOR_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/remote/bor.grpc.pb.cc"
    "${OUT_PATH_SYMLINK}/remote/bor.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/remote/bor.pb.cc"
    "${OUT_PATH_SYMLINK}/remote/bor.pb.h"
    "${OUT_PATH_SYMLINK}/remote/bor_mock.grpc.pb.h"
)
# cmake-format: on

add_custom_command(
  OUTPUT ${BOR_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${BOR_PROTO}"
  DEPENDS ${BOR_PROTO} generate_remote_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${BOR_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# MINING
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(MINING_PROTO "${PROTO_PATH}/txpool/mining.proto")

# cmake-format: off
set(MINING_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/txpool/mining.grpc.pb.cc"
    "${OUT_PATH_SYMLINK}/txpool/mining.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/txpool/mining.pb.cc"
    "${OUT_PATH_SYMLINK}/txpool/mining.pb.h"
    "${OUT_PATH_SYMLINK}/txpool/mining_mock.grpc.pb.h"
)
# cmake-format: on

create_symlink_target(generate_txpool_grpc_symlink "${OUT_PATH_SYMLINK}/txpool" "${OUT_PATH}/txpool")

add_custom_command(
  OUTPUT ${MINING_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${MINING_PROTO}"
  DEPENDS ${MINING_PROTO} generate_txpool_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${KV_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# TXPOOL
# ---------------------------------------------------------------------------------------------------------------------
# gRPC protocol interface file
set(TXPOOL_PROTO "${PROTO_PATH}/txpool/txpool.proto")

# cmake-format: off
set(TXPOOL_SOURCES_SYMLINK
    "${OUT_PATH_SYMLINK}/txpool/txpool.grpc.pb.cc"
    "${OUT_PATH_SYMLINK}/txpool/txpool.grpc.pb.h"
    "${OUT_PATH_SYMLINK}/txpool/txpool.pb.cc"
    "${OUT_PATH_SYMLINK}/txpool/txpool.pb.h"
    "${OUT_PATH_SYMLINK}/txpool/txpool_mock.grpc.pb.h"
)
# cmake-format: on

add_custom_command(
  OUTPUT ${TXPOOL_SOURCES_SYMLINK}
  COMMAND ${CMAKE_COMMAND} ARGS -E make_directory "${OUT_PATH}"
  COMMAND ${PROTOBUF_PROTOC} ARGS ${PROTOC_ARGS_GRPC} "${TXPOOL_PROTO}"
  DEPENDS ${TXPOOL_PROTO} generate_txpool_grpc_symlink
  COMMENT "Running C++ gRPC compiler on ${TXPOOL_PROTO}"
)
