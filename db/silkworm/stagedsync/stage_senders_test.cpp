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

#include <silkworm/rlp/encode.hpp>
#include <silkworm/chain/config.hpp>
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
#include <silkworm/chain/genesis.h>

using namespace evmc::literals;

#include "stagedsync.hpp"

constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};
constexpr evmc::bytes32 hash_2{0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

TEST_CASE("Stage Senders") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);
    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};

    Block block{};
    block.transactions.resize(1);

    auto sender_0{0xb685342b8c54347aad148e1f22eff3eb3eb29390_address};
    auto sender_1{0xb685342b8c54347aad148e1f22eff3eb3eb29389_address};
    auto sender_2{0xb685342b8c54347aad148e1f22eff3eb3eb29388_address};

    block.transactions[0].from = sender_0;

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes body_rlp{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(0, hash_0.bytes)), db::to_slice(body_rlp));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------


    block.transactions[0].from = sender_1;

    body_rlp = Bytes{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_1.bytes)), db::to_slice(body_rlp));

    // ---------------------------------------
    // Push third block
    // ---------------------------------------


    block.transactions[0].from = sender_2;

    body_rlp = Bytes{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_2.bytes)), db::to_slice(body_rlp));

    std::string genesis_data;
    genesis_data.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
    auto genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), db::to_slice(byte_view_of_c_str(config_data.c_str())));

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_2));

    stagedsync::check_stagedsync_error(stagedsync::stage_senders(txn, tmp_dir.path())); 

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};

    auto got_sender_0{db::from_slice(sender_table.find(db::to_slice(db::block_key(0, hash_0.bytes))).value)};
    auto got_sender_1{db::from_slice(sender_table.find(db::to_slice(db::block_key(1, hash_1.bytes))).value)};
    auto got_sender_2{db::from_slice(sender_table.find(db::to_slice(db::block_key(2, hash_2.bytes))).value)};

    REQUIRE(got_sender_0.compare(ByteView(sender_0.bytes)) == 0);
    REQUIRE(got_sender_1.compare(ByteView(sender_1.bytes)) == 0);
    REQUIRE(got_sender_2.compare(ByteView(sender_2.bytes)) == 0);
}

TEST_CASE("Unwind Senders") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);
    auto bodies_table{db::open_cursor(*txn, db::table::kBlockBodies)};

    Block block{};

    auto sender_0{0xb685342b8c54347aad148e1f22eff3eb3eb29390_address};
    auto sender_1{0xb685342b8c54347aad148e1f22eff3eb3eb29389_address};
    auto sender_2{0xb685342b8c54347aad148e1f22eff3eb3eb29388_address};

    block.transactions.resize(1);
    block.transactions[0].from = sender_0;

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes body_rlp{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(0, hash_0.bytes)), db::to_slice(body_rlp));

    // ---------------------------------------
    // Push second block
    // ---------------------------------------


    block.transactions[0].from = sender_1;

    body_rlp = Bytes{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(1, hash_1.bytes)), db::to_slice(body_rlp));

    // ---------------------------------------
    // Push third block
    // ---------------------------------------


    block.transactions[0].from = sender_2;

    body_rlp = Bytes{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(2, hash_2.bytes)), db::to_slice(body_rlp));

    std::string genesis_data;
    genesis_data.assign(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
    auto genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    auto config_data{genesis_json["config"].dump()};

    auto config_table{db::open_cursor(*txn, db::table::kConfig)};
    config_table.upsert(db::to_slice(full_view(hash_0.bytes)), db::to_slice(byte_view_of_c_str(config_data.c_str())));

    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    canonical_table.upsert(db::to_slice(db::block_key(0)), db::to_slice(hash_0));
    canonical_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(hash_1));
    canonical_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(hash_2));

    stagedsync::check_stagedsync_error(stagedsync::stage_senders(txn, tmp_dir.path())); 
    stagedsync::check_stagedsync_error(stagedsync::unwind_senders(txn, tmp_dir.path(), 1)); 

    auto sender_table{db::open_cursor(*txn, db::table::kSenders)};

    auto got_sender_0{db::from_slice(sender_table.find(db::to_slice(db::block_key(0, hash_0.bytes))).value)};
    auto got_sender_1{db::from_slice(sender_table.find(db::to_slice(db::block_key(1, hash_1.bytes))).value)};

    REQUIRE(got_sender_0.compare(ByteView(sender_0.bytes)) == 0);
    REQUIRE(got_sender_1.compare(ByteView(sender_1.bytes)) == 0);
    REQUIRE(!sender_table.seek(db::to_slice(db::block_key(2, hash_2.bytes))));
}
