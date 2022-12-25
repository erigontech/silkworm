/*
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
*/

#include "rec_split.hpp"

#include <cstdint>

#include <catch2/catch.hpp>

#include <silkworm/test/files.hpp>
#include <silkworm/test/log.hpp>

namespace silkworm::succinct {

TEST_CASE("RecSplit8", "[silkworm][recsplit]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporaryFile index_file;

    SECTION("keys") {
        RecSplit8 rs{
            /*.keys_count =*/ 2,
            /*.bucket_size =*/ 10,
            /*.index_path =*/ index_file.path(),
            /*.base_data_id =*/ 0,
            /*.salt =*/ 1,
        };
        CHECK_NOTHROW(rs.add_key("first_key", 0));
        CHECK_THROWS_AS(rs.build(), std::logic_error);
        CHECK_NOTHROW(rs.add_key("second_key", 0));
        CHECK_NOTHROW(rs.build());
    }
}

}  // namespace silkworm::succinct
