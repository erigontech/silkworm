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

hunter_add_package(Boost COMPONENTS filesystem)
find_package(Boost CONFIG REQUIRED COMPONENTS filesystem)

hunter_add_package(lmdb)
find_package(liblmdb CONFIG REQUIRED)

hunter_add_package(lmdbxx)
find_package(lmdbxx CONFIG REQUIRED)

file(GLOB SILKWORM_DB_SRC "*.cpp" ".hpp")
list(FILTER SILKWORM_DB_SRC EXCLUDE REGEX "_test\.cpp")

add_library(silkworm_db ${SILKWORM_DB_SRC})
# PUBLIC lmdbxx since we use its exceptions 
target_link_libraries(silkworm_db PUBLIC lmdbxx::lmdbxx PRIVATE Boost::filesystem liblmdb::lmdb)
