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

#include "stagedsync.hpp"

#include <string>

#include <silkworm/chain/config.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/common/magic_enum.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/buffer.hpp>
#include <silkworm/execution/execution.hpp>
#include <silkworm/db/stages.hpp>


namespace silkworm::stagedsync {

bool write_receipts = true;

StageResult execute(lmdb::Transaction* txn, ChainConfig config, uint64_t max_block, uint64_t* block_num) {
    db::Buffer buffer{txn};
    AnalysisCache analysis_cache;
    ExecutionStatePool state_pool;

    for (; *block_num <= max_block; ++*block_num) {
        std::optional<BlockWithHash> bh{db::read_block(*txn, *block_num, /*read_senders=*/true)};
        if (!bh) {
            return StageResult::kStageBadChainSequence;
        }

        auto [receipts, err]{execute_block(bh->block, buffer, config, &analysis_cache, &state_pool)};
        if (err != ValidationResult::kOk) {
            throw std::runtime_error("Validation error " + std::to_string(static_cast<int>(err)) + " at block " + std::to_string(*block_num));
        }

        if (write_receipts) {
            buffer.insert_receipts(*block_num, receipts);
        }

        if (*block_num % 1000 == 0) {
            SILKWORM_LOG(LogLevel::Info) << "Blocks <= " << block_num << " executed" << std::endl;
        }

        if (buffer.current_batch_size() >= kBatchSize) {
            buffer.write_to_db();
            return StageResult::kStageSuccess;
        }
    };

    buffer.write_to_db();
    return StageResult::kStageSuccess;
}

StageResult stage_execution(lmdb::DatabaseConfig db_config) {
    std::shared_ptr<lmdb::Environment> env{lmdb::get_env(db_config)};
    std::unique_ptr<lmdb::Transaction> txn{env->begin_ro_transaction()};

    auto config{db::read_chain_config(*txn)};

    uint64_t max_block{db::stages::get_stage_progress(*txn, db::stages::kBlockBodiesKey)};
    uint64_t block_num{db::stages::get_stage_progress(*txn, db::stages::kExecutionKey)};

    if (write_receipts && (!db::migration_happened(*txn, "receipts_cbor_encode") ||
                            !db::migration_happened(*txn, "receipts_store_logs_separately"))) {
        throw std::runtime_error("Legacy stored receipts are not supported");
    }

    // https://github.com/ledgerwatch/erigon/pull/1342
    if (!db::migration_happened(*txn, "acc_change_set_dup_sort_18") ||
        !db::migration_happened(*txn, "storage_change_set_dup_sort_22")) {
        throw std::runtime_error("Legacy change sets are not supported");
    }

    // https://github.com/ledgerwatch/erigon/pull/1358
    if (!db::migration_happened(*txn, "tx_table_4")) {
        throw std::runtime_error("Legacy stored transactions are not supported\n");
    }

    while (block_num <= max_block) {
        auto execution_code{execute(txn.get(), *config, max_block, &block_num)};
        if (execution_code != StageResult::kStageSuccess) {
            return execution_code;
        }
    };

    return StageResult::kStageSuccess;
}
}