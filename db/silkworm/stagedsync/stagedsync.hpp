/*
   Copyright 2020 - 2021 The Silkworm Authors

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
#include <silkworm/db/tables.hpp>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/stagedsync/util.hpp>
#include <vector>

#ifndef SILKWORM_STAGEDSYNC_HPP_
#define SILKWORM_STAGEDSYNC_HPP_

namespace silkworm::stagedsync {

constexpr size_t kBatchSize = 512 * kMebi;

typedef StageResult (*StageFunc)(lmdb::DatabaseConfig);
typedef StageResult (*UnwindFunc)(lmdb::DatabaseConfig, uint64_t);

struct Stage {
    StageFunc stage_func;
    UnwindFunc unwind_func;
    uint64_t id;
};

// Stage functions
StageResult stage_headers(lmdb::DatabaseConfig);
StageResult stage_blockhashes(lmdb::DatabaseConfig);
StageResult stage_bodies(lmdb::DatabaseConfig);
StageResult stage_senders(lmdb::DatabaseConfig);
StageResult stage_execution(lmdb::DatabaseConfig);
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
void hashstate_promote(lmdb::Transaction*, HashstateOperation);
void hashstate_promote_clean_code(lmdb::Transaction*, std::string);
void hashstate_promote_clean_state(lmdb::Transaction*, std::string);
/* **************************** */
StageResult stage_hashstate(lmdb::DatabaseConfig);
StageResult stage_interhashes(lmdb::DatabaseConfig);
StageResult stage_account_history(lmdb::DatabaseConfig);
StageResult stage_storage_history(lmdb::DatabaseConfig);
StageResult stage_log_index(lmdb::DatabaseConfig);
StageResult stage_tx_lookup(lmdb::DatabaseConfig);
// Unwind functions
StageResult no_unwind(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_senders(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_execution(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_hashstate(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_interhashes(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_account_history(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_storage_history(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_log_index(lmdb::DatabaseConfig, uint64_t);
StageResult unwind_tx_lookup(lmdb::DatabaseConfig, uint64_t);
// TODO

std::vector<Stage> get_default_stages();
}

#endif