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

#include <utility>
#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/infra/common/directories.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test/log.hpp>
#include <silkworm/node/test/snapshots.hpp>

namespace silkworm::snapshot {

class Snapshot_ForTest : public Snapshot {
  public:
    Snapshot_ForTest(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~Snapshot_ForTest() override { close(); }

    [[nodiscard]] SnapshotPath path() const override {
        return SnapshotPath::from(path_.parent_path(), kSnapshotV1, block_from_, block_to_, SnapshotType::headers);
    }

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
            CHECK(snapshot.fs_path().empty());
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
    huffman::Decompressor decoder{hello_world_snapshot_file.path()};
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
    huffman::Decompressor decoder{hello_world_snapshot_file.path()};
    Snapshot_ForTest tmp_snapshot{hello_world_snapshot_file.path(), 1'000, 2'000};
    tmp_snapshot.reopen_segment();
    CHECK_NOTHROW(tmp_snapshot.close());
}

// https://etherscan.io/block/1500013
TEST_CASE("HeaderSnapshot::header_by_number OK", "[silkworm][snapshot][index][.]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleHeaderSnapshotFile valid_header_snapshot{};
    test::SampleHeaderSnapshotPath header_snapshot_path{valid_header_snapshot.path()};  // necessary to tweak the block numbers
    HeaderIndex header_index{header_snapshot_path};
    REQUIRE_NOTHROW(header_index.build());

    HeaderSnapshot header_snapshot{header_snapshot_path.path(), header_snapshot_path.block_from(), header_snapshot_path.block_to()};
    header_snapshot.reopen_segment();
    header_snapshot.reopen_index();
    const auto header = header_snapshot.header_by_number(1'500'013);
    CHECK(header.has_value());
    if (header) {
        CHECK(header->hash() == 0xbef48d7de01f2d7ea1a7e4d1ed401f73d6d0257a364f6770b25ba51a123ac35f_bytes32);
        CHECK(header->parent_hash == 0x48a486d69a07e99ed6997eb0f9b8795e4e7d07c0ce5b8ee8e139d653fd1b01c3_bytes32);
        CHECK(header->ommers_hash == 0x7117cfc18ff9765fb04a0c223722d1cfd20a06e5d7a88778f9f66a2207b0638b_bytes32);
        CHECK(header->beneficiary == 0xea674fdde714fd979de3edf0f56aa9716b898ec8_address);
        CHECK(header->state_root == 0xac26fc90b79cd9304f03c925208e377d4e6e4b229ede56eb1728851e656791bc_bytes32);
        CHECK(header->transactions_root == 0xbc18a809c2ab84e0870c0be8de331e3e0498e31b22cdeb95e07f23a5c7f77f40_bytes32);
        CHECK(header->receipts_root == 0xc856db90a6c30a0264858960231c4a3f78f557ea83ea4d7ec260c691b0850523_bytes32);
        CHECK(header->logs_bloom == Bloom{});
        CHECK(header->difficulty == 0x1fad3d458f3e);
        CHECK(header->number == 1'500'013);
        CHECK(header->gas_limit == 4'712'388);

        CHECK(header->gas_used == 21'000);
        CHECK(header->timestamp == 1463003399);
        CHECK(header->extra_data == *from_hex("0xd783010400844765746887676f312e352e31856c696e7578"));
        CHECK(header->prev_randao == 0x799895e28a837bbdf28b8ecf5fc0e6251398ecb0ffc7ff5bbb457c21b14ce982_bytes32);
        CHECK(header->nonce == std::array<uint8_t, 8>{0x86, 0x98, 0x76, 0x20, 0x12, 0xb4, 0x6f, 0xef});
    }
}

// https://etherscan.io/block/1500013
TEST_CASE("BodySnapshot::body_by_number OK", "[silkworm][snapshot][index]") {
    test::SetLogVerbosityGuard guard{log::Level::kNone};
    test::SampleBodySnapshotFile valid_body_snapshot{};
    test::SampleBodySnapshotPath body_snapshot_path{valid_body_snapshot.path()};  // necessary to tweak the block numbers
    BodyIndex body_index{body_snapshot_path};
    CHECK_NOTHROW(body_index.build());

    BodySnapshot body_snapshot{body_snapshot_path.path(), body_snapshot_path.block_from(), body_snapshot_path.block_to()};
    body_snapshot.reopen_segment();
    body_snapshot.reopen_index();
    const auto body_for_storage = body_snapshot.body_by_number(1'500'013);
    CHECK(body_for_storage.has_value());
    if (body_for_storage) {
        CHECK(body_for_storage->base_txn_id == 7'341'273);
        CHECK(body_for_storage->txn_count == 1);
    }
}

}  // namespace silkworm::snapshot
