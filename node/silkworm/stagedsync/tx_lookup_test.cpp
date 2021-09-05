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
#include <silkworm/common/directories.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/execution.hpp>

using namespace evmc::literals;

#include "stagedsync.hpp"

constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};

using namespace silkworm;

static std::vector<Transaction> sample_transactions() {
    std::vector<Transaction> transactions;
    transactions.resize(2);

    transactions[0].nonce = 172339;
    transactions[0].max_priority_fee_per_gas = 50 * kGiga;
    transactions[0].max_fee_per_gas = 50 * kGiga;
    transactions[0].gas_limit = 90'000;
    transactions[0].to = 0xe5ef458d37212a06e3f59d40c454e76150ae7c32_address;
    transactions[0].value = 1'027'501'080 * kGiga;
    transactions[0].data = {};
    CHECK(transactions[0].set_v(27));
    transactions[0].r =
        intx::from_string<intx::uint256>("0x48b55bfa915ac795c431978d8a6a992b628d557da5ff759b307d495a36649353");
    transactions[0].s =
        intx::from_string<intx::uint256>("0x1fffd310ac743f371de3b9f7f9cb56c0b28ad43601b4ab949f53faa07bd2c804");

    transactions[1].type = Transaction::Type::kEip1559;
    transactions[1].nonce = 1;
    transactions[1].max_priority_fee_per_gas = 5 * kGiga;
    transactions[1].max_fee_per_gas = 30 * kGiga;
    transactions[1].gas_limit = 1'000'000;
    transactions[1].to = {};
    transactions[1].value = 0;
    transactions[1].data = *from_hex("602a6000556101c960015560068060166000396000f3600035600055");
    CHECK(transactions[1].set_v(37));
    transactions[1].r =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    transactions[1].s =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");

    return transactions;
}

TEST_CASE("Stage Transaction Lookups") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.chaindata().path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);
    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};
    auto transaction_table{db::open_cursor(*txn, db::table::kEthTx)};

    db::detail::BlockBodyForStorage block{};
    auto transactions{sample_transactions()};
    block.base_txn_id = 1;
    block.txn_count = 1;
    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes tx_rlp{};
    rlp::encode(tx_rlp, transactions[0]);
    auto tx_hash_1{keccak256(tx_rlp)};

    transaction_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_0.bytes)), db::to_slice(block.encode()));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------

    block.base_txn_id = 2;

    rlp::encode(tx_rlp, transactions[1]);
    auto tx_hash_2{keccak256(tx_rlp)};

    transaction_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(tx_rlp));
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_1.bytes)), db::to_slice(block.encode()));

    // Execute stage forward
    REQUIRE(stagedsync::stage_tx_lookup(txn, data_dir.etl().path()) == stagedsync::StageResult::kSuccess);

    SECTION("Forward checks and unwind") {
        auto lookup_table{db::open_cursor(*txn, db::table::kTxLookup)};
        // Retrieve numbers associated with hashes
        auto got_block_0{db::from_slice(lookup_table.find(db::to_slice(full_view(tx_hash_1.bytes))).value)};
        auto got_block_1{db::from_slice(lookup_table.find(db::to_slice(full_view(tx_hash_2.bytes))).value)};
        // Keys must be compact and equivalent to block number
        CHECK(got_block_0.compare(ByteView({1})) == 0);
        CHECK(got_block_1.compare(ByteView({2})) == 0);

        // Execute stage unwind
        REQUIRE(stagedsync::unwind_tx_lookup(txn, data_dir.etl().path(), 1) == stagedsync::StageResult::kSuccess);

        lookup_table = db::open_cursor(*txn, db::table::kTxLookup);
        // Unwind block should be still there
        got_block_0 = db::from_slice(lookup_table.find(db::to_slice(full_view(tx_hash_1.bytes))).value);
        REQUIRE(got_block_0.compare(ByteView({1})) == 0);
        // Block 2 must be absent due to unwind
        CHECK(!lookup_table.seek(db::to_slice(full_view(tx_hash_2.bytes))));
    }

    SECTION("Prune") {
        // Only leave block 2 alive
        REQUIRE(stagedsync::prune_tx_lookup(txn, data_dir.etl().path(), 2) == stagedsync::StageResult::kSuccess);

        auto lookup_table{db::open_cursor(*txn, db::table::kTxLookup)};
        // Unwind block should be still there
        auto got_block_1{db::from_slice(lookup_table.find(db::to_slice(full_view(tx_hash_2.bytes))).value)};
        REQUIRE(got_block_1.compare(ByteView({2})) == 0);
        // Block 2 must be absent due to unwind
        CHECK(!lookup_table.seek(db::to_slice(full_view(tx_hash_1.bytes))));
    }
}