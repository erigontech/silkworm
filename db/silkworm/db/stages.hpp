/*
   Copyright 2020 The Silkworm Authors

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

#pragma once
#ifndef SILKWORM_DB_STAGES_H_
#define SILKWORM_DB_STAGES_H_

#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>

/*
List of stages keys stored into SSP2 table
*/

namespace silkworm::db::stages {

constexpr const char* KAccountHistory_key{"AccountHistoryIndex"};
constexpr const char* KBlockHashes_key{"BlockHashes"};
constexpr const char* KBlockBodies_key{"BlockBodies"};
constexpr const char* KExecution_key{"Execution"};
constexpr const char* KFinish_key{"Finish"};
constexpr const char* KHashState_key{"HashState"};
constexpr const char* KHeaders_key{"Headers"};
constexpr const char* KIntermediateHashes_key{"IntermediateHashes"};
constexpr const char* KLogIndex_key{"LogIndex"};
constexpr const char* KSenders_key{"Senders"};
constexpr const char* KStorageHistoryIndex_key{"StorageHistoryIndex"};
constexpr const char* KTxLookup_key{"TxLookup"};
constexpr const char* KTxPool_key{"TxPool"};

// Gets the progress (block height) of any given stage
uint64_t get_stage_progress(std::unique_ptr<lmdb::Transaction>& txn, const char* stage_name);

// Sets the progress (block height) of any given stage
void set_stage_progress(std::unique_ptr<lmdb::Transaction>& txn, const char* stage_name, uint64_t block_num);

}  // namespace silkworm::db::stages

#endif  // !SILKWORM_DB_STAGES_H_
