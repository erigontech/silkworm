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

#include "stagedsync.hpp"

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

    // ---------------------------------------
    // Prepare
    // ---------------------------------------
    // This contract initially sets its 0th storage to 0x2a
    // and its 1st storage to 0x01c9.
    // When called, it updates its 0th storage to the input provided.
    Bytes contract_code{*from_hex("600035600055")};
    Bytes deployment_code{*from_hex("602a6000556101c960015560068060166000396000f3") + contract_code};
    Block block{};

    block.transactions.resize(1);
    block.transactions[0].data = deployment_code;
    block.transactions[0].gas_limit = block.header.gas_limit;
    block.transactions[0].max_priority_fee_per_gas = 0;  // EIP-1559
    block.transactions[0].max_fee_per_gas = 20 * kGiga;

    auto sender{0xb685342b8c54347aad148e1f22eff3eb3eb29391_address};
    block.transactions[0].from = sender;

    // ---------------------------------------
    // Push first block
    // ---------------------------------------
    Bytes body_rlp{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(1)), db::to_slice(body_rlp));
    auto contract_address{create_address(sender, /*nonce=*/0)};

    // ---------------------------------------
    // Execute second block
    // ---------------------------------------

    std::string new_val{"000000000000000000000000000000000000000000000000000000000000003e"};

    block.transactions[0].nonce = 1;
    block.transactions[0].value = 1000;

    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    body_rlp = Bytes{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(2)), db::to_slice(body_rlp));

    // ---------------------------------------
    // Execute third block
    // ---------------------------------------

    new_val = "000000000000000000000000000000000000000000000000000000000000003b";

    block.transactions[0].nonce = 2;
    block.transactions[0].value = 1000;

    block.transactions[0].to = contract_address;
    block.transactions[0].data = *from_hex(new_val);
    block.transactions[0].max_priority_fee_per_gas = 20 * kGiga;

    body_rlp = Bytes{};
    rlp::encode(body_rlp, block);
    bodies_table.upsert(db::to_slice(db::block_key(3)), db::to_slice(body_rlp));
    txn.commit();
    stagedsync::check_stagedsync_error(stagedsync::stage_senders(txn, tmp_dir.path())); 
}
