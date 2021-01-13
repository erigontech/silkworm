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

#pragma once
#ifndef SILKWORM_DB_STAGES_H_
#define SILKWORM_DB_STAGES_H_

#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/tables.hpp>

/*
List of stages keys stored into SSP2 table
*/

namespace silkworm::db::stages {

constexpr const char* kAccountHistoryKey{"AccountHistoryIndex"};
constexpr const char* kBlockHashesKey{"BlockHashes"};
constexpr const char* kBlockBodiesKey{"Bodies"};
constexpr const char* kExecutionKey{"Execution"};
constexpr const char* kFinishKey{"Finish"};
constexpr const char* kHashStateKey{"HashState"};
constexpr const char* kHeadersKey{"Headers"};
constexpr const char* kIntermediateHashesKey{"IntermediateHashes"};
constexpr const char* kLogIndexKey{"LogIndex"};
constexpr const char* kSendersKey{"Senders"};
constexpr const char* kStorageHistoryIndexKey{"StorageHistoryIndex"};
constexpr const char* kTxLookupKey{"TxLookup"};
constexpr const char* kTxPoolKey{"TxPool"};

// Gets the progress (block height) of any given stage
uint64_t get_stage_progress(lmdb::Transaction& txn, const char* stage_name);

// Sets the progress (block height) of any given stage
void set_stage_progress(lmdb::Transaction& txn, const char* stage_name, uint64_t block_num);

}  // namespace silkworm::db::stages

#endif  // !SILKWORM_DB_STAGES_H_
