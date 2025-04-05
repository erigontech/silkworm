// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/tables.hpp>

/*
    List of stages keys stored into SyncStage table
*/

namespace silkworm::db::stages {

using datastore::kvdb::ROTxn;
using datastore::kvdb::RWTxn;

//! \brief Headers are downloaded, their Proof-Of-Work validity and chaining is verified
inline constexpr std::string_view kHeadersKey{"Headers"};

//! \brief Headers Number are written, fills blockHash => number bucket
inline constexpr std::string_view kBlockHashesKey{"BlockHashes"};

//! \brief Block bodies are downloaded, TxHash and UncleHash are getting verified
inline constexpr std::string_view kBlockBodiesKey{"Bodies"};

//! \brief "From" recovered from signatures
inline constexpr std::string_view kSendersKey{"Senders"};

//! \brief Executing each block w/o building a trie
inline constexpr std::string_view kExecutionKey{"Execution"};

//! \brief Generate intermediate hashes, calculate the state root hash
inline constexpr std::string_view kIntermediateHashesKey{"IntermediateHashes"};

//! \brief Apply Keccak256 to all the keys in the state
inline constexpr std::string_view kHashStateKey{"HashState"};

//! \brief Generating history index for accounts
inline constexpr std::string_view kHistoryIndexKey{"HistoryIndex"};

//! \brief Generating history index for accounts
inline constexpr std::string_view kAccountHistoryIndexKey{"AccountHistoryIndex"};

//! \brief Generating history index for storage
inline constexpr std::string_view kStorageHistoryIndexKey{"StorageHistoryIndex"};

//! \brief Generating logs index (from receipts)
inline constexpr std::string_view kLogIndexKey{"LogIndex"};

//! \brief Generating call traces index
inline constexpr std::string_view kCallTracesKey{"CallTraces"};

//! \brief Generating transactions lookup index
inline constexpr std::string_view kTxLookupKey{"TxLookup"};

//! \brief Triggers stage
inline constexpr std::string_view kTriggersStageKey{"Triggers"};

//! \brief Nominal stage after all other stages
inline constexpr std::string_view kFinishKey{"Finish"};

//! \brief List of all known stages
inline constexpr std::string_view kAllStages[]{
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
    kTriggersStageKey,
    kFinishKey,
};

//! \brief Stages won't log their "start" if segment is below this threshold
inline constexpr size_t kSmallBlockSegmentWidth{0};

//! \brief Some stages will use this threshold to determine if worth regen vs incremental
inline constexpr size_t kLargeBlockSegmentWorthRegen{100'000};

//! \brief Reads from db the progress (block number) of the provided stage name
//! \param [in] txn : a reference to a ro/rw db transaction
//! \param [in] stage_name : the name of the requested stage (must be known see kAllStages[])
//! \return The actual chain block number the stage has reached
BlockNum read_stage_progress(ROTxn& txn, std::string_view stage_name);

//! \brief Reads from db the prune progress (block number) of the provided stage name
//! \param [in] txn : a reference to a ro/rw db transaction
//! \param [in] stage_name : the name of the requested stage (must be known see kAllStages[])
//! \return The actual chain block number the stage has pruned its data up to
//! \remarks A pruned block_num means the prune stage function has run up to this block_num
BlockNum read_stage_prune_progress(ROTxn& txn, std::string_view stage_name);

//! \brief Writes into db the progress (block number) for the provided stage name
//! \param [in] txn : a reference to a rw db transaction
//! \param [in] stage_name : the name of the involved stage (must be known see kAllStages[])
//! \param [in] block_num : the actual chain block number the stage must record
void write_stage_progress(RWTxn& txn, std::string_view stage_name, BlockNum block_num);

//! \brief Writes into db the prune progress (block number) for the provided stage name
//! \param [in] txn : a reference to a rw db transaction
//! \param [in] stage_name : the name of the involved stage (must be known see kAllStages[])
//! \param [in] block_num : the actual chain block number the stage must record
//! \remarks A pruned block_num means the prune stage function has run up to this block_num
void write_stage_prune_progress(RWTxn& txn, std::string_view stage_name, BlockNum block_num);

//! \brief Whether the provided stage name is known to Silkworm
//! \param [in] stage_name : The name of the stage to check for
//! \return Whether it exists in kAllStages[]
bool is_known_stage(std::string_view stage_name);

}  // namespace silkworm::db::stages
