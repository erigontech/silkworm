/*
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
*/

#include "difficulty.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("DifficultyTest34") {
    uint64_t block_number{0x33e140};
    uint64_t block_timestamp{0x04bdbdaf};
    uint64_t parent_difficulty{0x7268db7b46b0b154};
    uint64_t parent_timestamp{0x04bdbdaf};
    bool parent_has_uncles{false};

    intx::uint256 difficulty{canonical_difficulty(block_number, block_timestamp, parent_difficulty, parent_timestamp,
                                                  parent_has_uncles, kMainnetConfig)};
    CHECK(difficulty == 0x72772897b619876a);
}
}  // namespace silkworm
