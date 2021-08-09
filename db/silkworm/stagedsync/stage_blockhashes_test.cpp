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
#include <evmc/evmc.hpp>

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

using namespace evmc::literals;

constexpr evmc::bytes32 hash_0{0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32};
constexpr evmc::bytes32 hash_1{0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32};
constexpr evmc::bytes32 hash_2{0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

TEST_CASE("Stage Block Hashes") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    CHECK_NOTHROW(data_dir.create_tree());

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    // ---------------------------------------
    // Prepare
    // ---------------------------------------
    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    auto expected_block_number_0{db::block_key(1)};
    auto expected_block_number_1{db::block_key(2)};
    auto expected_block_number_2{db::block_key(3)};

    canonical_table.insert(db::to_slice(expected_block_number_0), db::to_slice(hash_0));
    canonical_table.insert(db::to_slice(expected_block_number_1), db::to_slice(hash_1));
    canonical_table.insert(db::to_slice(expected_block_number_2), db::to_slice(hash_2));
    txn.commit();
    // Execute checks
    CHECK(stagedsync::stage_blockhashes(txn, data_dir.get_etl_path()) == stagedsync::StageResult::kSuccess);
    // Hopefully not Post-Mortem checks
    auto blockhashes_table{db::open_cursor(*txn, db::table::kHeaderNumbers)};

    auto actual_block_number_0{db::from_slice(blockhashes_table.find(db::to_slice(hash_0)).value)};
    auto actual_block_number_1{db::from_slice(blockhashes_table.find(db::to_slice(hash_1)).value)};
    auto actual_block_number_2{db::from_slice(blockhashes_table.find(db::to_slice(hash_2)).value)};

    REQUIRE(actual_block_number_0.compare(expected_block_number_0) == 0);
    REQUIRE(actual_block_number_1.compare(expected_block_number_1) == 0);
    REQUIRE(actual_block_number_2.compare(expected_block_number_2) == 0);
}

TEST_CASE("Unwind Block Hashes") {
    using namespace silkworm;

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    CHECK_NOTHROW(data_dir.create_tree());

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    // ---------------------------------------
    // Prepare
    // ---------------------------------------
    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    auto expected_block_number_0{db::block_key(1)};
    auto expected_block_number_1{db::block_key(2)};
    auto expected_block_number_2{db::block_key(3)};

    canonical_table.insert(db::to_slice(expected_block_number_0), db::to_slice(hash_0));
    canonical_table.insert(db::to_slice(expected_block_number_1), db::to_slice(hash_1));
    canonical_table.insert(db::to_slice(expected_block_number_2), db::to_slice(hash_2));
    txn.commit();
    // Execute checks
    CHECK_NOTHROW(stagedsync::check_stagedsync_error(stagedsync::stage_blockhashes(txn, data_dir.get_etl_path())));
    CHECK_NOTHROW(stagedsync::check_stagedsync_error(stagedsync::unwind_blockhashes(txn, data_dir.get_etl_path(), 1)));
    // Hopefully not Post-Mortem checks
    auto blockhashes_table{db::open_cursor(*txn, db::table::kHeaderNumbers)};

    auto actual_block_number_0{db::from_slice(blockhashes_table.find(db::to_slice(hash_0)).value)};

    REQUIRE(actual_block_number_0.compare(expected_block_number_0) == 0);
    REQUIRE(!blockhashes_table.seek(db::to_slice(hash_1)));
    REQUIRE(!blockhashes_table.seek(db::to_slice(hash_2)));
}
