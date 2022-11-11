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

#include "snapshot.hpp"

#include <tuple>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>

namespace silkworm {

class Snapshot_ForTest : public Snapshot {
  public:
    using Snapshot::Snapshot;
    void reopen_index() override {}
    void close_index() override {}
};

TEST_CASE("Snapshot::Snapshot", "[silkworm][snapshot][snapshot]") {
    SECTION("valid") {
        std::vector<std::pair<BlockNum, BlockNum>> block_ranges{
            {0, 0},
            {1'000, 2'000}};
        for (const auto& [block_from, block_to] : block_ranges) {
            Snapshot_ForTest snapshot{std::filesystem::path{}, block_from, block_to};
            CHECK(snapshot.path().empty());
            CHECK(snapshot.block_from() == block_from);
            CHECK(snapshot.block_to() == block_to);
        }
    }
    SECTION("invalid") {
        CHECK_THROWS_AS(Snapshot_ForTest(std::filesystem::path{}, 1'000, 999), std::logic_error);
    }
}

}  // namespace silkworm
