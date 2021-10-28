/*
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
*/

#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/chain/genesis.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/test_context.hpp>
#include <silkworm/common/test_util.hpp>
#include <silkworm/db/stages.hpp>

using namespace evmc::literals;

#include "stagedsync.hpp"

static constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
static constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};
static constexpr evmc::bytes32 hash_2{0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

using namespace silkworm;

TEST_CASE("Stage Senders") {
    test::Context context;
    stagedsync::TransactionManager txn{context.txn()};

    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transaction_table{db::open_cursor(*txn, db::table::kBlockTransactions)};

    db::detail::BlockBodyForStorage block{};
    auto transactions{test::sample_transactions()};
    block.base_txn_id = 1;
    block.txn_count = 1;

    auto sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes tx_rlp{};
    rlp::encode(tx_rlp, transactions[0]);

    transaction_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_0.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------

    block.base_txn_id = 2;

    rlp::encode(tx_rlp, transactions[1]);
    transaction_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_1.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push third block
    // ---------------------------------------

    block.base_txn_id = 0;
    block.txn_count = 0;

    bodies_table.upsert(db::to_slice(db::block_key(3, hash_2.bytes)), db::to_slice(block.encode()));

    std::string genesis_data = read_genesis_data(kMainnetConfig.chain_id);
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());
    CHECK(genesis_json.contains("config"));

    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), mdbx::slice{config_data.c_str()});

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(3)), db::to_slice(hash_2));
    db::stages::write_stage_progress(*txn, db::stages::kBlockBodiesKey, 3);

    stagedsync::success_or_throw(stagedsync::stage_senders(txn, context.dir().etl().path()));

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};
    auto got_sender_0{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(1))).value)};
    auto got_sender_1{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(2))).value)};
    auto expected_sender{ByteView(sender.bytes, kAddressLength)};

    REQUIRE(got_sender_0.compare(expected_sender) == 0);
    REQUIRE(got_sender_1.compare(expected_sender) == 0);
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(3)), false));
}

TEST_CASE("Unwind Senders") {
    test::Context context;
    stagedsync::TransactionManager txn{context.txn()};

    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transaction_table{db::open_cursor(*txn, db::table::kBlockTransactions)};

    db::detail::BlockBodyForStorage block{};
    auto transactions{test::sample_transactions()};
    block.base_txn_id = 1;
    block.txn_count = 1;

    auto sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes tx_rlp{};
    rlp::encode(tx_rlp, transactions[0]);

    transaction_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_0.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------

    block.base_txn_id = 2;

    rlp::encode(tx_rlp, transactions[1]);
    transaction_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_1.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push third block
    // ---------------------------------------

    block.base_txn_id = 0;
    block.txn_count = 0;

    bodies_table.upsert(db::to_slice(db::block_key(3, hash_2.bytes)), db::to_slice(block.encode()));

    std::string genesis_data = read_genesis_data(kMainnetConfig.chain_id);
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());
    CHECK(genesis_json.contains("config"));
    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), mdbx::slice{config_data.c_str()});

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(3)), db::to_slice(hash_2));
    db::stages::write_stage_progress(*txn, db::stages::kBlockBodiesKey, 3);

    stagedsync::success_or_throw(stagedsync::stage_senders(txn, context.dir().etl().path()));
    stagedsync::success_or_throw(stagedsync::unwind_senders(txn, context.dir().etl().path(), 1));

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};
    auto got_sender_0{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(1))).value)};

    auto expected_sender{ByteView(sender.bytes, kAddressLength)};

    REQUIRE(got_sender_0.compare(expected_sender) == 0);
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(2)), false));
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(3)), false));
}

TEST_CASE("Prune Senders") {
    test::Context context;
    stagedsync::TransactionManager txn{context.txn()};

    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transaction_table{db::open_cursor(*txn, db::table::kBlockTransactions)};

    db::detail::BlockBodyForStorage block{};
    auto transactions{test::sample_transactions()};
    block.base_txn_id = 1;
    block.txn_count = 1;

    auto sender{0xc15eb501c014515ad0ecb4ecbf75cc597110b060_address};

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes tx_rlp{};
    rlp::encode(tx_rlp, transactions[0]);

    transaction_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_0.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------

    block.base_txn_id = 2;

    rlp::encode(tx_rlp, transactions[1]);
    transaction_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_1.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push third block
    // ---------------------------------------

    block.base_txn_id = 0;
    block.txn_count = 0;

    bodies_table.upsert(db::to_slice(db::block_key(3, hash_2.bytes)), db::to_slice(block.encode()));

    std::string genesis_data = read_genesis_data(kMainnetConfig.chain_id);
    auto genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), mdbx::slice{config_data.c_str()});

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(3)), db::to_slice(hash_2));
    db::stages::write_stage_progress(*txn, db::stages::kBlockBodiesKey, 3);

    stagedsync::success_or_throw(stagedsync::stage_senders(txn, context.dir().etl().path()));
    // We prune from Block 2, thus deleting block 1
    stagedsync::success_or_throw(stagedsync::prune_senders(txn, context.dir().etl().path(), 2));

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};
    auto got_sender_1{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(2))).value)};
    auto got_start_key{db::from_slice(sender_table.to_first().key).substr(0, 8)};

    auto expected_sender{ByteView(sender.bytes, kAddressLength)};

    REQUIRE(got_sender_1.compare(expected_sender) == 0);
    REQUIRE(got_start_key.compare(db::block_key(2)) == 0);
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(3)), false));
}
