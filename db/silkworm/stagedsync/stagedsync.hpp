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

#ifndef SILKWORM_STAGEDSYNC_HPP_
#define SILKWORM_STAGEDSYNC_HPP_

namespace silkworm::stagedsync {

StageResult stage_blockhashes(std::string db_path, lmdb::Transaction* txn, uint64_t from = UINT64_MAX);
StageResult stage_senders(std::string db_path, lmdb::Transaction* txn, uint64_t from = UINT64_MAX);
StageResult stage_execution(lmdb::Transaction* txn, uint64_t from = UINT64_MAX);
StageResult stage_hashstate(std::string db_path, lmdb::Transaction* txn, uint64_t from = UINT64_MAX);
StageResult stage_history_index(std::string db_path, lmdb::Transaction* txn, bool storage, uint64_t from = UINT64_MAX);
StageResult stage_log_index(std::string db_path, lmdb::Transaction* txn, uint64_t from = UINT64_MAX);
StageResult stage_tx_lookup(std::string db_path, lmdb::Transaction* txn, uint64_t from = UINT64_MAX);

}

#endif