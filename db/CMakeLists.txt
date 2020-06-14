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

find_package(Boost 1.62 REQUIRED COMPONENTS filesystem)

if(MSVC)
  find_package(LMDB)
else()
  find_path(LMDB_INCLUDE_DIR  NAMES lmdb.h PATHS "$ENV{LMDB_DIR}/include")
  find_library(LMDB_LIBRARIES NAMES lmdb   PATHS "$ENV{LMDB_DIR}/lib" )
endif()
if(NOT LMDB_LIBRARIES OR NOT LMDB_INCLUDE_DIR)
  message(FATAL_ERROR "lmdb library not found")
endif()

file(GLOB db_SRC "*.cpp")
list(FILTER db_SRC EXCLUDE REGEX "_test\.cpp")

add_library(db ${db_SRC})
target_include_directories(db PUBLIC ${Boost_INCLUDE_DIRS} ${LMDB_INCLUDE_DIR})
target_link_libraries(db PUBLIC ${Boost_LIBRARIES} ${LMDB_LIBRARIES})
