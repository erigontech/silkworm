#[[
   Copyright 2020-2021 The SilkRpc Authors

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

#find_package(Protobuf REQUIRED)
#include_directories(${Protobuf_INCLUDE_DIRS})
#include_directories(${CMAKE_CURRENT_BINARY_DIR})
#protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS sentry.proto)
#protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS EXPORT_MACRO DLL_EXPORT sentry.proto)
#protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS DESCRIPTORS PROTO_DESCS sentry.proto)
#protobuf_generate_python(PROTO_PY sentry.proto)
#add_executable(bar bar.cc ${PROTO_SRCS} ${PROTO_HDRS})
#target_link_libraries(bar ${Protobuf_LIBRARIES})

# Find Protobuf installation
set(protobuf_MODULE_COMPATIBLE TRUE)
find_package(Protobuf CONFIG REQUIRED)
find_program(PROTOBUF_PROTOC protoc REQUIRED)

# Find gRPC installation
find_package(gRPC CONFIG REQUIRED)
find_program(GRPC_CPP_PLUGIN_EXECUTABLE grpc_cpp_plugin REQUIRED)

# ---------------------------------------------------------------------------------------------------------------------
# types proto file
set(PROTO_PATH "${CMAKE_CURRENT_SOURCE_DIR}/proto")
set(TYPES_PROTO "${PROTO_PATH}/types/types.proto")

# types sources
set(TYPES_PROTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/types/types.pb.cc")
set(TYPES_PROTO_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/types/types.pb.h")

add_custom_command(
        OUTPUT "${TYPES_PROTO_SOURCES}" "${TYPES_PROTO_HEADERS}"
        COMMAND ${PROTOBUF_PROTOC}
        ARGS --cpp_out "${CMAKE_CURRENT_SOURCE_DIR}"
          -I "${PROTO_PATH}"
          "${TYPES_PROTO}"
        DEPENDS "${TYPES_PROTO}"
)

# ---------------------------------------------------------------------------------------------------------------------
# gRPC proto file
set(SENTRY_PROTO "${PROTO_PATH}/p2psentry/sentry.proto")

# Generate sources
set(SENTRY_PROTO_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.pb.cc")
set(SENTRY_PROTO_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.pb.h")
set(SENTRY_GRPC_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.grpc.pb.cc")
set(SENTRY_GRPC_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/p2psentry/sentry.grpc.pb.h")

add_custom_command(
    OUTPUT "${SENTRY_PROTO_SOURCES}" "${SENTRY_PROTO_HEADERS}" "${SENTRY_GRPC_SOURCES}" "${SENTRY_GRPC_HEADERS}"
    COMMAND ${PROTOBUF_PROTOC}
    ARGS --grpc_out "${CMAKE_CURRENT_SOURCE_DIR}"
      --cpp_out "${CMAKE_CURRENT_SOURCE_DIR}"
      -I "${PROTO_PATH}"
      --plugin=protoc-gen-grpc="${GRPC_CPP_PLUGIN_EXECUTABLE}"
      "${SENTRY_PROTO}"
    DEPENDS "${SENTRY_PROTO}"
)

add_custom_target(
    generate_sentry_grpc
    DEPENDS "${SENTRY_PROTO_SOURCES}" "${SENTRY_PROTO_HEADERS}" "${SENTRY_GRPC_SOURCES}" "${SENTRY_GRPC_HEADERS}"
            "${TYPES_PROTO_SOURCES}" "${TYPES_PROTO_HEADERS}"
)
