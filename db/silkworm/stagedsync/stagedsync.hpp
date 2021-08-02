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

#ifndef SILKWORM_DB_STAGEDSYNC_STAGEDSYNC_HPP_
#define SILKWORM_DB_STAGEDSYNC_STAGEDSYNC_HPP_

#include <filesystem>
#include <vector>

#include <silkworm/db/tables.hpp>
#include <silkworm/stagedsync/transaction_manager.hpp>
#include <silkworm/stagedsync/util.hpp>

namespace silkworm::stagedsync {

constexpr size_t kDefaultBatchSize = 512 * kMebi;

typedef StageResult (*StageFunc)(TransactionManager &, const std::filesystem::path &etl_path);
typedef StageResult (*UnwindFunc)(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);

struct Stage {
    StageFunc stage_func;
    UnwindFunc unwind_func;
    uint64_t id;
};

// Stage functions
StageResult stage_headers(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_blockhashes(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_bodies(TransactionManager &, const std::filesystem::path &etl_pat);
StageResult stage_senders(TransactionManager &, const std::filesystem::path &etl_pat);
StageResult stage_execution(TransactionManager &, const std::filesystem::path &etl_path, size_t batch_size);
inline StageResult stage_execution(TransactionManager &txn, const std::filesystem::path &etl_path) {
    return stage_execution(txn, etl_path, kDefaultBatchSize);
}

/* HashState Promotion Functions*/

/*
    * Operation is used to distinguish what bucket we want to generated
    * HashAccount is for genenerating HashedAccountBucket
    * HashStorage is for genenerating HashedStorageBucket
    * Code generates hashed key => code_hash mapping

*/
enum class HashstateOperation {
    HashAccount,
    HashStorage,
    Code,
};

void hashstate_promote(mdbx::txn &, HashstateOperation);
void hashstate_promote_clean_code(mdbx::txn &, std::string);
void hashstate_promote_clean_state(mdbx::txn &, std::string);

/* **************************** */
StageResult stage_hashstate(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_interhashes(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_account_history(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_storage_history(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_log_index(TransactionManager &, const std::filesystem::path &etl_path);
StageResult stage_tx_lookup(TransactionManager &, const std::filesystem::path &etl_path);

// Unwind functions
StageResult no_unwind(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_senders(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_execution(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_hashstate(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_interhashes(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_account_history(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_storage_history(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_log_index(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);
StageResult unwind_tx_lookup(TransactionManager &, const std::filesystem::path &etl_path, uint64_t unwind_to);

std::vector<Stage> get_default_stages();

}  // namespace silkworm::stagedsync

#endif  // SILKWORM_DB_STAGEDSYNC_STAGEDSYNC_HPP_
