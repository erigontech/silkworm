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

#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/stagedsync/recovery/recovery_farm.hpp>

#include "stagedsync.hpp"

namespace silkworm::stagedsync {

namespace fs = std::filesystem;

StageResult stage_senders(TransactionManager& txn, const std::filesystem::path& etl_path, uint64_t) {
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path, /* flush size */ 512_Mebi);

    // Create farm instance and do work
    // Max number of workers is set to number of cores - 1 (one thread is left for main)
    recovery::RecoveryFarm farm(*txn, std::thread::hardware_concurrency() - 1, kDefaultRecoverySenderBatch, collector);

    auto block_from{db::stages::read_stage_progress(*txn, db::stages::kSendersKey)};
    auto block_to{db::stages::read_stage_progress(*txn, db::stages::kBlockBodiesKey)};

    const StageResult res{farm.recover(block_from, block_to)};

    if (res != StageResult::kSuccess) {
        return res;
    }

    txn.commit();

    return res;
}

StageResult unwind_senders(TransactionManager& txn, const std::filesystem::path& etl_path, uint64_t unwind_point) {
    fs::create_directories(etl_path);
    etl::Collector collector(etl_path, /* flush size */ 512_Mebi);

    // Create farm instance and do work
    recovery::RecoveryFarm farm(*txn, std::thread::hardware_concurrency(), kDefaultBatchSize, collector);

    const StageResult res{farm.unwind(unwind_point)};

    if (res != StageResult::kSuccess) {
        return res;
    }

    txn.commit();

    return res;
}

StageResult prune_senders(TransactionManager& txn, const std::filesystem::path&, uint64_t prune_from) {
    SILKWORM_LOG(LogLevel::Info) << "Pruning Sender Recovery from: " << prune_from << std::endl;
    auto new_tail{db::block_key(prune_from)};
    auto unwind_table{db::open_cursor(*txn, db::table::kSenders)};
    truncate_table_from(unwind_table, new_tail, /* reverse = */ true);
    SILKWORM_LOG(LogLevel::Info) << "Pruning Sender Recovery finished..." << std::endl;
    return StageResult::kSuccess;
}

}  // namespace silkworm::stagedsync
