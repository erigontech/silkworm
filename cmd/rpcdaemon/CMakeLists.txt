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
    add_link_options(/STACK:10000000)
elseif (${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
    add_link_options(-Wl,-stack_size -Wl,0x1000000)
endif()

find_package(absl REQUIRED)
find_package(CLI11 REQUIRED)
find_package(gRPC REQUIRED)
find_package(Protobuf REQUIRED)
if(SILKWORM_USE_MIMALLOC)
    find_package(mimalloc 2.0 REQUIRED)
endif()

if(MSVC)
    add_compile_options(/bigobj)
endif()

# Silkrpc toolbox
add_executable(silkrpc_toolbox
    silkrpc_toolbox.cpp
    ethbackend_async.cpp ethbackend_coroutines.cpp ethbackend.cpp
    kv_seek_async_callback.cpp kv_seek_async_coroutines.cpp kv_seek_async.cpp kv_seek.cpp kv_seek_both.cpp)
target_include_directories(silkrpc_toolbox PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(silkrpc_toolbox absl::flags_parse gRPC::grpc++ protobuf::libprotobuf silkrpc)

# Silkrpc daemon
set(SILKRPC_DAEMON_LIBRARIES
    silkworm-buildinfo
    silkrpc
    absl::flags_parse
    CLI11::CLI11)
if(SILKWORM_USE_MIMALLOC)
    list(APPEND SILKRPC_DAEMON_LIBRARIES mimalloc)
endif()

add_executable(silkrpcdaemon silkrpc_daemon.cpp ../common/common.cpp)
target_include_directories(silkrpcdaemon PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(silkrpcdaemon PRIVATE ${SILKRPC_DAEMON_LIBRARIES})
