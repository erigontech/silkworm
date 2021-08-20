/*
   Copyright 2021 The Silkworm Authors

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

#include "util.hpp"

#include <catch2/catch.hpp>
#include <ethash/keccak.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/data_dir.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/execution/address.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/stagedsync/transaction_manager.hpp>
#include <silkworm/trie/vector_root.hpp>
#include <silkworm/types/account.hpp>
#include <silkworm/types/block.hpp>

using namespace silkworm;

TEST_CASE("Check Truncate tables, reverse = true") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    Bytes value{db::block_key(0)};  // Same value for each entry
    // Cursor to be opened does not matter
    auto account_history_table{db::open_cursor(*txn, db::table::kAccountHistory)};

    for (int i = 100; i >= 0; i--) {
        account_history_table.upsert(db::to_slice(db::block_key(i)), db::to_slice(value));
    }
    // Check if works if cut in half
    auto cut_point{db::block_key(50)};
    stagedsync::truncate_table_from(account_history_table, cut_point, true);
    CHECK(db::from_slice(account_history_table.to_first().key).compare(db::block_key(50)) == 0);
    // Check if works if same arguments
    stagedsync::truncate_table_from(account_history_table, cut_point, true);
    CHECK(db::from_slice(account_history_table.to_first().key).compare(db::block_key(50)) == 0);
}

TEST_CASE("Check Truncate tables, reverse = false") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.get_chaindata_path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    Bytes value{db::block_key(0)};  // Same value for each entry
    // Cursor to be opened does not matter
    auto account_history_table{db::open_cursor(*txn, db::table::kAccountHistory)};

    for (int i = 100; i >= 0; i--) {
        account_history_table.upsert(db::to_slice(db::block_key(i)), db::to_slice(value));
    }
    // Check if works if cut in half
    auto cut_point{db::block_key(50)};
    stagedsync::truncate_table_from(account_history_table, cut_point, false);
    CHECK(db::from_slice(account_history_table.to_last().key).compare(db::block_key(49)) == 0);
    // Check if works if same arguments
    stagedsync::truncate_table_from(account_history_table, cut_point, false);
    CHECK(db::from_slice(account_history_table.to_last().key).compare(db::block_key(49)) == 0);
}
