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
#include <utility>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/test/log.hpp>
#include <silkworm/test/snapshot_files.hpp>

namespace silkworm {

class Snapshot_ForTest : public Snapshot {
  public:
    Snapshot_ForTest(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~Snapshot_ForTest() override { close(); }

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
            CHECK(snapshot.item_count() == 0);
            CHECK(snapshot.empty());
        }
    }
    SECTION("invalid") {
        CHECK_THROWS_AS(Snapshot_ForTest(std::filesystem::path{}, 1'000, 999), std::logic_error);
    }
}

TEST_CASE("Snapshot::reopen_segment", "[silkworm][snapshot][snapshot]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::TemporarySnapshotFile tmp_snapshot_file{test::SnapshotHeader{}};
    auto snapshot{std::make_unique<Snapshot_ForTest>(tmp_snapshot_file.path(), 0, 0)};
    snapshot->reopen_segment();
}

TEST_CASE("Snapshot::for_each_item", "[silkworm][snapshot][snapshot]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::HelloWorldSnapshotFile hello_world_snapshot_file{};
    Decompressor decoder{hello_world_snapshot_file.path()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path(), 1'000, 2'000};
    tmp_snapshot.reopen_segment();
    CHECK(!tmp_snapshot.empty());
    CHECK(tmp_snapshot.item_count() == 1);
    tmp_snapshot.for_each_item([&](const auto& word_item) {
        CHECK(std::string{word_item.value.cbegin(), word_item.value.cend()} == "hello, world");
        CHECK(word_item.position == 0);
        CHECK(word_item.offset == 0);
        return true;
    });
}

TEST_CASE("Snapshot::close", "[silkworm][snapshot][snapshot]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::HelloWorldSnapshotFile hello_world_snapshot_file{};
    Decompressor decoder{hello_world_snapshot_file.path()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path(), 1'000, 2'000};
    tmp_snapshot.reopen_segment();
    CHECK_NOTHROW(tmp_snapshot.close());
}

}  // namespace silkworm
