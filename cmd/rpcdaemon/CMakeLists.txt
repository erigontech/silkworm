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
if(SILKRPC_USE_MIMALLOC)
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

# TO BE REMOVED: START: temporarily disable warnings entirely to make silkrpc_toolbox compile as it is
get_target_property(SILKRPCTOOLBOX_COMPILE_OPTIONS silkrpc_toolbox COMPILE_OPTIONS)
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wall")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Werror")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wextra")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wshadow")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wimplicit-fallthrough")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wsign-conversion")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wno-missing-field-initializers")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wnon-virtual-dtor")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-Wthread-safety")
list(REMOVE_ITEM SILKRPCTOOLBOX_COMPILE_OPTIONS "-pedantic")
set_property(TARGET silkrpc_toolbox PROPERTY COMPILE_OPTIONS ${SILKRPCTOOLBOX_COMPILE_OPTIONS})
# TO BE REMOVED: END: temporarily disable warnings entirely to make silkrpc_toolbox compile as it is

# Silkrpc daemon
set(SILKRPC_DAEMON_LIBRARIES
    silkworm-buildinfo
    silkrpc
    absl::flags_parse
    CLI11::CLI11)
if(SILKRPC_USE_MIMALLOC)
    list(APPEND SILKRPC_DAEMON_LIBRARIES mimalloc)
endif()

add_executable(silkrpcdaemon silkrpc_daemon.cpp ../common/common.cpp)
target_include_directories(silkrpcdaemon PUBLIC ${CMAKE_SOURCE_DIR})
target_link_libraries(silkrpcdaemon PRIVATE ${SILKRPC_DAEMON_LIBRARIES})

# TO BE REMOVED: START: temporarily disable warnings entirely to make silkrpcdaemon compile as it is
get_target_property(SILKRPCDAEMON_COMPILE_OPTIONS silkrpcdaemon COMPILE_OPTIONS)
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wall")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Werror")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wextra")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wshadow")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wimplicit-fallthrough")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wsign-conversion")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "$<$<COMPILE_LANGUAGE:CXX>:-Wold-style-cast>")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wno-missing-field-initializers")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wnon-virtual-dtor")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-Wthread-safety")
list(REMOVE_ITEM SILKRPCDAEMON_COMPILE_OPTIONS "-pedantic")
set_property(TARGET silkrpcdaemon PROPERTY COMPILE_OPTIONS ${SILKRPCDAEMON_COMPILE_OPTIONS})
# TO BE REMOVED: END: temporarily disable warnings entirely to make silkrpcdaemon compile as it is
