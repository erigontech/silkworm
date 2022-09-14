/*
   Copyright 2022 The Silkworm Authors

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

#include <silkworm/db/tables.hpp>

/*
    List of stages keys stored into SyncStage table
*/

namespace silkworm::db::stages {

//! \brief Headers are downloaded, their Proof-Of-Work validity and chaining is verified
inline constexpr const char* kHeadersKey{"Headers"};

//! \brief Headers Number are written, fills blockHash => number bucket
inline constexpr const char* kBlockHashesKey{"BlockHashes"};

//! \brief Block bodies are downloaded, TxHash and UncleHash are getting verified
inline constexpr const char* kBlockBodiesKey{"Bodies"};

//! \brief "From" recovered from signatures
inline constexpr const char* kSendersKey{"Senders"};

//! \brief Executing each block w/o building a trie
inline constexpr const char* kExecutionKey{"Execution"};

//! \brief Generate intermediate hashes, calculate the state root hash
inline constexpr const char* kIntermediateHashesKey{"IntermediateHashes"};

//! \brief Apply Keccak256 to all the keys in the state
inline constexpr const char* kHashStateKey{"HashState"};

//! \brief Generating history index for accounts
inline constexpr const char* kHistoryIndexKey{"HistoryIndex"};

//! \brief Generating history index for accounts
inline constexpr const char* kAccountHistoryIndexKey{"AccountHistoryIndex"};

//! \brief Generating history index for storage
inline constexpr const char* kStorageHistoryIndexKey{"StorageHistoryIndex"};

//! \brief Generating logs index (from receipts)
inline constexpr const char* kLogIndexKey{"LogIndex"};

//! \brief Generating call traces index
inline constexpr const char* kCallTracesKey{"CallTraces"};

//! \brief Generating transactions lookup index
inline constexpr const char* kTxLookupKey{"TxLookup"};

//! \brief Starts Backend
inline constexpr const char* kTxPoolKey{"TxPool"};

//! \brief Nominal stage after all other stages
inline constexpr const char* kFinishKey{"Finish"};

//! \brief Not an actual stage rather placeholder for global unwind point
inline constexpr const char* kUnwindKey{"Unwind"};

//! \brief Create block for mining
inline constexpr const char* kMiningCreateBlockKey{"MiningCreateBlock"};

//! \brief  Execute mining
inline constexpr const char* kMiningExecutionKey{"MiningExecution"};

//! \brief Mining completed
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
    kHistoryIndexKey,
    kAccountHistoryIndexKey,
    kStorageHistoryIndexKey,
    kLogIndexKey,
    kCallTracesKey,
    kTxLookupKey,
    kTxPoolKey,
    kFinishKey,
    kUnwindKey,
};

//! \brief Stages won't log their "start" if segment is below this threshold
inline constexpr size_t kSmallBlockSegmentWidth{16};

//! \brief Some stages will use this threshold to determine if worth regen vs incremental
inline constexpr size_t kLargeBlockSegmentWorthRegen{100'000};

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
