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

#ifndef SILKWORM_DB_TABLES_HPP_
#define SILKWORM_DB_TABLES_HPP_

#include <optional>

#include <silkworm/db/mdbx.hpp>

/*
Part of the compatibility layer with the Turbo-Geth DB format;
see its common/dbutils/bucket.go.
*/
namespace silkworm::db::table {

inline constexpr VersionBase kRequiredSchemaVersion{3, 0, 0};  // We're compatible with this

inline constexpr const char* kLastHeaderKey{"LastHeader"};

/* Canonical tables */

// block_num_u64 (BE) -> address + previous_account (encoded)
inline constexpr db::MapConfig kAccountChangeSet{"AccountChangeSet", mdbx::key_mode::usual, mdbx::value_mode::multi};

inline constexpr db::MapConfig kAccountHistory{"AccountHistory"};
inline constexpr db::MapConfig kBlockBodies{"BlockBody"};

// block_num_u64 (BE) -> header_hash
inline constexpr db::MapConfig kCanonicalHashes{"CanonicalHeader"};

// block_num_u64 (BE) + hash -> header (RLP)
inline constexpr db::MapConfig kHeaders{"Header"};

// block_num_u64 (BE) + hash -> total_difficulty (RLP)
inline constexpr db::MapConfig kDifficulty{"HeadersTotalDifficulty"};

inline constexpr db::MapConfig kBlockReceipts{"Receipt"};
inline constexpr db::MapConfig kBloomBitsIndex{"BloomBitsIndex"};
inline constexpr db::MapConfig kBloomBits{"BloomBits"};
inline constexpr db::MapConfig kBodiesSnapshotInfo{"BodiesSnapshotInfo"};
inline constexpr db::MapConfig kCallFromIndex{"CallFromIndex"};
inline constexpr db::MapConfig kCallToIndex{"CallToIndex"};
inline constexpr db::MapConfig kCallTraceSet{"CallTraceSet", mdbx::key_mode::usual, mdbx::value_mode::multi};
inline constexpr db::MapConfig kCode{"Code"};
inline constexpr db::MapConfig kConfig{"Config"};
inline constexpr db::MapConfig kContractCode{"HashedCodeHash"};
inline constexpr db::MapConfig kDatabaseInfo{"DbInfo"};
inline constexpr db::MapConfig kBlockTransactions{"BlockTransaction"};
inline constexpr db::MapConfig kHashedAccounts{"HashedAccount"};
inline constexpr db::MapConfig kHashedStorage{"HashedStorage", mdbx::key_mode::usual, mdbx::value_mode::multi};
inline constexpr db::MapConfig kHeadBlock{"LastBlock"};
inline constexpr db::MapConfig kHeadHeader{"LastHeader"};
inline constexpr db::MapConfig kHeaderNumbers{"HeaderNumber"};
inline constexpr db::MapConfig kHeadersSnapshotInfo{"HeadersSnapshotInfo"};
inline constexpr db::MapConfig kIncarnationMap{"IncarnationMap"};
inline constexpr db::MapConfig kLogAddressIndex{"LogAddressIndex"};
inline constexpr db::MapConfig kLogTopicIndex{"LogTopicIndex"};
inline constexpr db::MapConfig kLogs{"TransactionLog"};
inline constexpr db::MapConfig kMigrations{"Migration"};
inline constexpr db::MapConfig kPlainContractCode{"PlainCodeHash"};
inline constexpr db::MapConfig kPlainState{"PlainState", mdbx::key_mode::usual, mdbx::value_mode::multi};
inline constexpr db::MapConfig kSenders{"TxSender"};
inline constexpr db::MapConfig kSequence{"Sequence"};
inline constexpr db::MapConfig kSnapshotInfo{"SnapshotInfo"};
inline constexpr db::MapConfig kStateSnapshotInfo{"StateSnapshotInfo"};

// block_num_u64 (BE) + address + incarnation_u64 (BE) ->
// plain_storage_location (32 bytes) + previous_value (no leading zeros)
inline constexpr db::MapConfig kStorageChangeSet{"StorageChangeSet", mdbx::key_mode::usual, mdbx::value_mode::multi};

inline constexpr db::MapConfig kStorageHistory{"StorageHistory"};

// Progress for stages
inline constexpr db::MapConfig kSyncStageProgress{"SyncStage"};

// Unwind point for stages
inline constexpr db::MapConfig kSyncStageUnwind{"SyncStageUnwind"};

inline constexpr db::MapConfig kTrieOfAccounts{"TrieAccount"};
inline constexpr db::MapConfig kTrieOfStorage{"TrieStorage"};
inline constexpr db::MapConfig kTxLookup{"BlockTransactionLookup"};

inline constexpr db::MapConfig kChainDataTables[]{
    kAccountChangeSet,
    kAccountHistory,
    kBlockBodies,
    kBlockReceipts,
    kBloomBits,
    kBloomBitsIndex,
    kBodiesSnapshotInfo,
    kCallFromIndex,
    kCallToIndex,
    kCallTraceSet,
    kCanonicalHashes,
    kHeaders,
    kDifficulty,
    kCode,
    kConfig,
    kContractCode,
    kDatabaseInfo,
    kBlockTransactions,
    kHashedAccounts,
    kHashedStorage,
    kHeadBlock,
    kHeadHeader,
    kHeaderNumbers,
    kHeadersSnapshotInfo,
    kIncarnationMap,
    kLogAddressIndex,
    kLogTopicIndex,
    kLogs,
    kMigrations,
    kPlainContractCode,
    kPlainState,
    kSenders,
    kSequence,
    kSnapshotInfo,
    kStateSnapshotInfo,
    kStorageChangeSet,
    kStorageHistory,
    kSyncStageProgress,
    kSyncStageUnwind,
    kTrieOfAccounts,
    kTrieOfStorage,
    kTxLookup,
};

//! \brief Ensures all defined tables are present in db with consistent flags. Should a table not exist it gets created
void check_or_create_chaindata_tables(mdbx::txn& txn);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_HPP_
