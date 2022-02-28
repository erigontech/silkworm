/*
   Copyright 2021-2022 The Silkworm Authors

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

#ifndef SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_
#define SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_

// See https://github.com/ledgerwatch/erigon/blob/devel/eth/stagedsync/README.md

#include <filesystem>
#include <vector>

#include <silkworm/db/stages.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/stagedsync/common.hpp>

namespace silkworm::stagedsync {

typedef StageResult (*StageFunc)(db::RWTxn&, const std::filesystem::path& etl_path, uint64_t prune_from);

struct Stage {
    StageFunc stage_func;
    uint64_t id;
};

// Stage functions
StageResult stage_headers(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);

/* **************************** */
StageResult stage_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);
StageResult stage_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from = 0);

// Unwind functions
StageResult unwind_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_log_index(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);
StageResult unwind_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t unwind_to);

// Prune functions
StageResult prune_account_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_storage_history(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);
StageResult prune_tx_lookup(db::RWTxn& txn, const std::filesystem::path& etl_path, uint64_t prune_from);


}  // namespace silkworm::stagedsync

#endif  // SILKWORM_STAGEDSYNC_STAGEDSYNC_HPP_
