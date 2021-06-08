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

typedef StageResult (*StageFunc)(std::string, lmdb::Transaction*);
typedef StageResult (*UnwindFunc)(std::string, lmdb::Transaction*, uint64_t);

struct Stage {
    StageFunc stage_func;
    UnwindFunc unwind_func;
    uint64_t id;
};

// Stage functions
StageResult stage_blockhashes(std::string db_path, lmdb::Transaction* txn);
StageResult stage_senders(std::string db_path, lmdb::Transaction* txn);
StageResult stage_execution(std::string db_path, lmdb::Transaction* txn);
StageResult stage_hashstate(std::string db_path, lmdb::Transaction* txn);
StageResult stage_account_history(std::string db_path, lmdb::Transaction* txn);
StageResult stage_storage_history(std::string db_path, lmdb::Transaction* txn);
StageResult stage_log_index(std::string db_path, lmdb::Transaction* txn);
StageResult stage_tx_lookup(std::string db_path, lmdb::Transaction* txn);
// Unwind Function
// TODO

std::vector<Stage> get_default_stages();
}

#endif