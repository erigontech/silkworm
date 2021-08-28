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

#ifndef SILKWORM_DB_STAGES_HPP_
#define SILKWORM_DB_STAGES_HPP_

#include <silkworm/db/tables.hpp>

/*
List of stages keys stored into SyncStage table
*/

namespace silkworm::db::stages {

// clang-format off

constexpr const char* kHeadersKey{"Headers"};                         // Headers are downloaded, their Proof-Of-Work validity and chaining is verified
constexpr const char* kBlockHashesKey{"BlockHashes"};                 // Headers Number are written, fills blockHash => number bucket
constexpr const char* kBlockBodiesKey{"Bodies"};                      // Block bodies are downloaded, TxHash and UncleHash are getting verified
constexpr const char* kSendersKey{"Senders"};                         // "From" recovered from signatures
constexpr const char* kExecutionKey{"Execution"};                     // Executing each block w/o building a trie
constexpr const char* kTranslationKey{"Translation"};                 // Translation each marked for translation contract (from EVM to TEVM)
constexpr const char* kIntermediateHashesKey{"IntermediateHashes"};   // Generate intermediate hashes, calculate the state root hash
constexpr const char* kHashStateKey{"HashState"};                     // Apply Keccak256 to all the keys in the state
constexpr const char* kAccountHistoryIndexKey{"AccountHistoryIndex"}; // Generating history index for accounts
constexpr const char* kStorageHistoryIndexKey{"StorageHistoryIndex"}; // Generating history index for storage
constexpr const char* kLogIndexKey{"LogIndex"};                       // Generating logs index (from receipts)
constexpr const char* kCallTracesKey{"CallTraces"};                   // Generating call traces index
constexpr const char* kTxLookupKey{"TxLookup"};                       // Generating transactions lookup index
constexpr const char* kTxPoolKey{"TxPool"};                           // Starts Backend
constexpr const char* kFinishKey{"Finish"};                           // Nominal stage after all above listed stages

constexpr const char* kMiningCreateBlockKey{"MiningCreateBlock"};     // Create block for mining
constexpr const char* kMiningExecutionKey{"MiningExecution"};         // Execute mining
constexpr const char* kMiningFinishKey{"MiningFinish"};               // Mining completed

// clang-format on

constexpr const char* kAllStages[]{
    kHeadersKey,
    kBlockHashesKey,
    kBlockBodiesKey,
    kSendersKey,
    kExecutionKey,
    kTranslationKey,
    kIntermediateHashesKey,
    kHashStateKey,
    kAccountHistoryIndexKey,
    kStorageHistoryIndexKey,
    kLogIndexKey,
    kCallTracesKey,
    kTxLookupKey,
    kTxPoolKey,
    kFinishKey,
};

// Gets the progress (block height) of any given stage
uint64_t get_stage_progress(mdbx::txn& txn, const char* stage_name);

// Sets the progress (block height) of any given stage
void set_stage_progress(mdbx::txn& txn, const char* stage_name, uint64_t block_num);

// Gets the invalidation point for the given stage
// Invalidation point means that that stage needs to roll back to the invalidation
// point and be redone
uint64_t get_stage_unwind(mdbx::txn& txn, const char* stage_name);

// Sets the invalidation point for the given stage
void set_stage_unwind(mdbx::txn& txn, const char* stage_name, uint64_t block_num);

// Clears the invalidation point for the given stage
void clear_stage_unwind(mdbx::txn& txn, const char* stage_name);

// Returns whether the stage name is coded
bool is_known_stage(const char* name);

}  // namespace silkworm::db::stages

#endif  // !SILKWORM_DB_STAGES_HPP_
