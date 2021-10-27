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

// Headers are downloaded, their Proof-Of-Work validity and chaining is verified
inline constexpr const char* kHeadersKey{"Headers"};

// Headers Number are written, fills blockHash => number bucket
inline constexpr const char* kBlockHashesKey{"BlockHashes"};

// Block bodies are downloaded, TxHash and UncleHash are getting verified
inline constexpr const char* kBlockBodiesKey{"Bodies"};

// "From" recovered from signatures
inline constexpr const char* kSendersKey{"Senders"};

// Executing each block w/o building a trie
inline constexpr const char* kExecutionKey{"Execution"};

// Generate intermediate hashes, calculate the state root hash
inline constexpr const char* kIntermediateHashesKey{"IntermediateHashes"};

// Apply Keccak256 to all the keys in the state
inline constexpr const char* kHashStateKey{"HashState"};

// Generating history index for accounts
inline constexpr const char* kAccountHistoryIndexKey{"AccountHistoryIndex"};

// Generating history index for storage
inline constexpr const char* kStorageHistoryIndexKey{"StorageHistoryIndex"};

// Generating logs index (from receipts)
inline constexpr const char* kLogIndexKey{"LogIndex"};

// Generating call traces index
inline constexpr const char* kCallTracesKey{"CallTraces"};

// Generating transactions lookup index
inline constexpr const char* kTxLookupKey{"TxLookup"};

// Starts Backend
inline constexpr const char* kTxPoolKey{"TxPool"};

// Nominal stage after all other stages
inline constexpr const char* kFinishKey{"Finish"};

// Create block for mining
inline constexpr const char* kMiningCreateBlockKey{"MiningCreateBlock"};

//  Execute mining
inline constexpr const char* kMiningExecutionKey{"MiningExecution"};

// Mining completed
inline constexpr const char* kMiningFinishKey{"MiningFinish"};

//! \brief List of all known stages
inline constexpr const char* kAllStages[]{
    kHeadersKey,
    kBlockHashesKey,
    kBlockBodiesKey,
    kSendersKey,
    kExecutionKey,
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

//! \brief Reads from db the progress (block height) of the provided stage name
//! \param [in] txn : a reference to a ro/rw db transaction
//! \param [in] stage_name : the name of the requested stage (must be known see kAllStages[])
//! \return The actual chain height (BlockNum) the stage has reached
BlockNum read_stage_progress(mdbx::txn& txn, const char* stage_name);

//! \brief Reads from db the prune progress (block height) of the provided stage name
//! \param [in] txn : a reference to a ro/rw db transaction
//! \param [in] stage_name : the name of the requested stage (must be known see kAllStages[])
//! \return The actual chain height (BlockNum) the stage has pruned its data up to
//! \remarks A pruned height X means the prune stage function has run up to this block
BlockNum read_stage_prune_progress(mdbx::txn& txn, const char* stage_name);

//! \brief Writes into db the progress (block height) for the provided stage name
//! \param [in] txn : a reference to a rw db transaction
//! \param [in] stage_name : the name of the involved stage (must be known see kAllStages[])
//! \param [in] block_num : the actual chain height (BlockNum) the stage must record
void write_stage_progress(mdbx::txn& txn, const char* stage_name, BlockNum block_num);

//! \brief Writes into db the prune progress (block height) for the provided stage name
//! \param [in] txn : a reference to a rw db transaction
//! \param [in] stage_name : the name of the involved stage (must be known see kAllStages[])
//! \param [in] block_num : the actual chain height (BlockNum) the stage must record
//! \remarks A pruned height X means the prune stage function has run up to this block
void write_stage_prune_progress(mdbx::txn& txn, const char* stage_name, BlockNum block_num);

//! \brief Reads from db the invalidation point (block height) of provided stage name. Invalidation point means that
//! that stage needs to roll back to the invalidation point and re-execute its work for subsequent blocks (if any)
//! \param [in] txn : a reference to a ro/rw db transaction
//! \param [in] stage_name : the name of the requested stage (must be known see kAllStages[])
//! \return The invalidation point
//! \remarks An invalidation point == 0 means there is no invalidation point. BlockNum 0 is the genesis and you can't
//! unwind it
BlockNum read_stage_unwind(mdbx::txn& txn, const char* stage_name);

//! \brief Writes into db the invalidation point (block height) for the provided stage name
//! \param [in] txn : a reference to a rw db transaction
//! \param [in] stage_name : the name of the involved stage (must be known see kAllStages[])
//! \param [in] block_num : the actual chain invalidation point (BlockNum) the stage must record. If omitted the value
//! defaults to 0 which means to clear any previously recorded invalidation point.
void write_stage_unwind(mdbx::txn& txn, const char* stage_name, BlockNum block_num = 0);

//! \brief Whether the provided stage name is known to Silkworm
//! \param [in] stage_name : The name of the stage to check for
//! \return Whether it exists in kAllStages[]
bool is_known_stage(const char* stage_name);

}  // namespace silkworm::db::stages

#endif  // !SILKWORM_DB_STAGES_HPP_
