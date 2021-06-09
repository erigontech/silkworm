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

typedef StageResult (*StageFunc)(lmdb::DatabaseConfig);
typedef StageResult (*UnwindFunc)(lmdb::DatabaseConfig, uint64_t);

struct Stage {
    StageFunc stage_func;
    UnwindFunc unwind_func;
    uint64_t id;
};

// Stage functions
StageResult stage_headers(lmdb::DatabaseConfig db_config);
StageResult stage_blockhashes(lmdb::DatabaseConfig db_config);
StageResult stage_bodies(lmdb::DatabaseConfig db_config);
StageResult stage_senders(lmdb::DatabaseConfig db_config);
StageResult stage_execution(lmdb::DatabaseConfig db_config);
StageResult stage_hashstate(lmdb::DatabaseConfig db_config);
StageResult stage_account_history(lmdb::DatabaseConfig db_config);
StageResult stage_storage_history(lmdb::DatabaseConfig db_config);
StageResult stage_log_index(lmdb::DatabaseConfig db_config);
StageResult stage_tx_lookup(lmdb::DatabaseConfig db_config);
// Unwind Function
// TODO

std::vector<Stage> get_default_stages();
}

#endif