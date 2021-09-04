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
#include <silkworm/chain/protocol_param.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/db/stages.hpp>

#include "stagedsync.hpp"

namespace silkworm {

static constexpr evmc::bytes32 block_hashes[] = {
    0x3ac225168df54212a25c1c01fd35bebfea408fdac2e31ddd6f80a4bbf9a5f1cb_bytes32,
    0xb5553de315e0edf504d9150af82dafa5c4667fa618ed0a6f19c69b41166c5510_bytes32,
    0x0b42b6393c1f53060fe3ddbfcd7aadcca894465a5a438f69c87d790b2299b9b2_bytes32};

TEST_CASE("Stage Block Hashes") {
    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    CHECK_NOTHROW(data_dir.deploy());

    // Initialize temporary Database
    db::EnvConfig db_config{data_dir.chaindata().path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    stagedsync::TransactionManager txn{env};
    db::table::create_all(*txn);

    // ---------------------------------------
    // Prepare
    // ---------------------------------------
    auto canonical_table{db::open_cursor(*txn, db::table::kCanonicalHashes)};
    for (int i = 0; i < 3; ++i) {
        Bytes block_key{db::block_key(i + 1)};
        canonical_table.insert(db::to_slice(block_key), db::to_slice(block_hashes[i]));
    }
    canonical_table.close();
    CHECK_NOTHROW(txn.commit());

    // Execute stage forward
    auto forward_result{stagedsync::stage_blockhashes(txn, data_dir.etl().path())};
    REQUIRE(forward_result == stagedsync::StageResult::kSuccess);

    CHECKED_IF(forward_result == stagedsync::StageResult::kSuccess) {
        // Verify execution has written correctly
        auto blockhashes_table{db::open_cursor(*txn, db::table::kHeaderNumbers)};
        REQUIRE((*txn).get_map_stat(blockhashes_table.map()).ms_entries == 3);

        bool forward_double_check_result{true};
        for (int i = 0; i < 3 && forward_double_check_result; ++i) {
            auto data{blockhashes_table.find(db::to_slice(block_hashes[i]), false)};
            if (!data.done) {
                forward_double_check_result = false;
                continue;
            }
            auto reached_block_num = endian::load_big_u64(static_cast<uint8_t*>(data.value.iov_base));
            if (reached_block_num != i + 1) {
                forward_double_check_result = false;
            }
        }
        REQUIRE(forward_double_check_result);
        CHECKED_IF(forward_double_check_result){

            // Unwind stage
            auto unwind_result{stagedsync::unwind_blockhashes(txn, data_dir.etl().path(), 1)};
            REQUIRE(unwind_result == stagedsync::StageResult::kSuccess);

            // Check records have decreased to 1
            CHECKED_IF(unwind_result == stagedsync::StageResult::kSuccess){
                blockhashes_table = db::open_cursor(*txn, db::table::kHeaderNumbers);
                REQUIRE((*txn).get_map_stat(blockhashes_table.map()).ms_entries == 1);
                auto data{blockhashes_table.find(db::to_slice(block_hashes[0]), false)};
                REQUIRE(data.done);
            }
        }
    }
}
}  // namespace silkworm
