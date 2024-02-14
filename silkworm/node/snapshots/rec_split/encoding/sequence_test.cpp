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

#include "sequence.hpp"

#include <sstream>

#include <catch2/catch.hpp>

#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::snapshots::rec_split::encoding {

TEST_CASE("Uint64Sequence", "[silkworm][recsplit][sequence]") {
    test_util::SetLogVerbosityGuard guard{log::Level::kNone};
    Uint64Sequence output_sequence{0, 11, 21, 31, 41, 51, 61};

    std::stringstream ss;
    ss << output_sequence;

    Uint64Sequence input_sequence;
    ss >> input_sequence;

    CHECK(input_sequence == output_sequence);
}

}  // namespace silkworm::snapshots::rec_split::encoding
