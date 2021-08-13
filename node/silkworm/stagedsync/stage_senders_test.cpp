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
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/state/memory_buffer.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

using namespace evmc::literals;

#include "stagedsync.hpp"

constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};
constexpr evmc::bytes32 hash_2{0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

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
    transactions[0].set_v(27);
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
    transactions[1].set_v(37);
    transactions[1].r =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");
    transactions[1].s =
        intx::from_string<intx::uint256>("0x52f8f61201b2b11a78d6e866abc9c3db2ae8631fa656bfe5cb53668255367afb");

    return transactions;
}

TEST_CASE("Stage Senders") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
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

    std::string genesis_data;
    read_genesis_data(static_cast<uint32_t>(KnownChainIds::kMainnetId), genesis_data);

    auto genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), mdbx::slice{config_data.c_str()});

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(3)), db::to_slice(hash_2));
    db::stages::set_stage_progress(*txn, db::stages::kBlockBodiesKey, 3);

    stagedsync::check_stagedsync_error(stagedsync::stage_senders(txn, data_dir.get_etl_path()));

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};
    auto got_sender_0{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(1))).value)};
    auto got_sender_1{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(2))).value)};
    auto expected_sender{ByteView(sender.bytes, kAddressLength)};

    REQUIRE(got_sender_0.compare(expected_sender) == 0);
    REQUIRE(got_sender_1.compare(expected_sender) == 0);
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(3)), false));
}

TEST_CASE("Unwind Senders") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
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

    std::string genesis_data;
    read_genesis_data(static_cast<uint32_t>(KnownChainIds::kMainnetId), genesis_data);

    auto genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), mdbx::slice{config_data.c_str()});

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(3)), db::to_slice(hash_2));
    db::stages::set_stage_progress(*txn, db::stages::kBlockBodiesKey, 3);

    stagedsync::check_stagedsync_error(stagedsync::stage_senders(txn, tmp_dir.path()));
    stagedsync::check_stagedsync_error(stagedsync::unwind_senders(txn, tmp_dir.path(), 1));

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};
    auto got_sender_0{db::from_slice(sender_table.lower_bound(db::to_slice(db::block_key(1))).value)};

    auto expected_sender{ByteView(sender.bytes, kAddressLength)};

    REQUIRE(got_sender_0.compare(expected_sender) == 0);
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(2)), false));
    REQUIRE(!sender_table.lower_bound(db::to_slice(db::block_key(3)), false));
}
