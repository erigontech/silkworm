#[[
   Copyright 2020-2021 The Silkworm Authors

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

find_package(absl CONFIG REQUIRED)
find_package(Boost CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_DB_SRC CONFIGURE_DEPENDS "*.cpp" "*.hpp" "*.c" "*.h" "*.cc")
list(FILTER SILKWORM_DB_SRC EXCLUDE REGEX "_test\.cpp$")

add_library(silkworm_db
        ${SILKWORM_DB_SRC}
        "${CMAKE_SOURCE_DIR}/interfaces/sentry.grpc.pb.cc"
        "${CMAKE_SOURCE_DIR}/interfaces/sentry.pb.cc"
        "${CMAKE_SOURCE_DIR}/interfaces/types.pb.cc")

add_dependencies(silkworm_db generate_sentry_grpc)

set_source_files_properties("${CMAKE_SOURCE_DIR}/interfaces/sentry.grpc.pb.cc" PROPERTIES GENERATED TRUE)
set_source_files_properties("${CMAKE_SOURCE_DIR}/interfaces/sentry.pb.cc" PROPERTIES GENERATED TRUE)
set_source_files_properties("${CMAKE_SOURCE_DIR}/interfaces/types.pb.cc" PROPERTIES GENERATED TRUE)

get_filename_component(SILKWORM_MAIN_DIR ../ ABSOLUTE)
target_include_directories(silkworm_db PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}
        "${SILKWORM_MAIN_DIR}/magic_enum/include"
        "${CMAKE_SOURCE_DIR}/interfaces")

set(SILKWORM_DB_PUBLIC_LIBS silkworm_core mdbx-static absl::flat_hash_map absl::flat_hash_set absl::btree roaring
        nlohmann_json::nlohmann_json gRPC::grpc++ protobuf::libprotobuf)
set(SILKWORM_DB_PRIVATE_LIBS cborcpp)

if(MSVC)
  list(APPEND SILKWORM_DB_PRIVATE_LIBS ntdll.lib)
endif(MSVC)

target_link_libraries(silkworm_db PUBLIC ${SILKWORM_DB_PUBLIC_LIBS} PRIVATE ${SILKWORM_DB_PRIVATE_LIBS})

#if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
#  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++20 -fcoroutines")
#endif()
#
#set_property(TARGET silkworm_db PROPERTY CXX_STANDARD 20)

# test ----------------------------------------------------------------------------------------------------------------

find_package(Catch2 CONFIG REQUIRED)

file(GLOB_RECURSE SILKWORM_DB_TESTS CONFIGURE_DEPENDS "*_test.cpp")

add_executable(silkworm_db_test
        "${CMAKE_SOURCE_DIR}/cmd/unit_test.cpp"
        ${SILKWORM_DB_TESTS})
target_link_libraries(silkworm_db_test silkworm_db Catch2::Catch2)

set_property(TARGET silkworm_db_test PROPERTY CXX_STANDARD 20)

if(MSVC)
  target_compile_options(silkworm_db_test PRIVATE /EHsc)
  #else()
  #  target_compile_options(stage1_test PRIVATE -fno-exceptions)
endif()