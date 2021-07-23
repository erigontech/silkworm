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

#include <vector>

#include <silkworm/db/tables.hpp>
#include <silkworm/stagedsync/util.hpp>

#ifndef SILKWORM_STAGEDSYNC_HPP_
#define SILKWORM_STAGEDSYNC_HPP_

namespace silkworm::stagedsync {

constexpr size_t kDefaultBatchSize = 512 * kMebi;

typedef StageResult (*StageFunc)(db::EnvConfig);
typedef StageResult (*UnwindFunc)(db::EnvConfig, uint64_t);

struct Stage {
    StageFunc stage_func;
    UnwindFunc unwind_func;
    uint64_t id;
};

// Stage functions
StageResult stage_headers(db::EnvConfig);
StageResult stage_blockhashes(db::EnvConfig);
StageResult stage_bodies(db::EnvConfig);
StageResult stage_senders(db::EnvConfig);
StageResult stage_execution(db::EnvConfig, std::optional<uint64_t> to_block = std::nullopt,
                            size_t batch_size = kDefaultBatchSize);
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
StageResult stage_hashstate(db::EnvConfig);
StageResult stage_interhashes(db::EnvConfig);
StageResult stage_account_history(db::EnvConfig, mdbx::txn *external_txn = nullptr);
StageResult stage_storage_history(db::EnvConfig, mdbx::txn *external_txn = nullptr);
StageResult stage_log_index(db::EnvConfig);
StageResult stage_tx_lookup(db::EnvConfig);
// Unwind functions
StageResult no_unwind(db::EnvConfig, uint64_t);
StageResult unwind_senders(db::EnvConfig, uint64_t);
StageResult unwind_execution(db::EnvConfig, uint64_t);
StageResult unwind_hashstate(db::EnvConfig, uint64_t);
StageResult unwind_interhashes(db::EnvConfig, uint64_t);
StageResult unwind_account_history(db::EnvConfig, uint64_t);
StageResult unwind_storage_history(db::EnvConfig, uint64_t);
StageResult unwind_log_index(db::EnvConfig, uint64_t);
StageResult unwind_tx_lookup(db::EnvConfig, uint64_t);
// TODO

std::vector<Stage> get_default_stages();

}  // namespace silkworm::stagedsync

#endif
