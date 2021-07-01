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

/* Canonical tables */
constexpr db::MapConfig kMAIN_DBI{nullptr};
constexpr db::MapConfig kAccountHistory{"AccountHistory"};
constexpr db::MapConfig kBlockBodies{"BlockBody"};

constexpr db::MapConfig kCanonicalHashes{"CanonicalHeader"};    // block_num_u64 (BE) -> header_hash
constexpr db::MapConfig kHeaders{"Header"};                     // block_num_u64 (BE) + hash -> header (RLP)
constexpr db::MapConfig kDifficulty{"HeadersTotalDifficulty"};  // block_num_u64 (BE) + hash -> total_difficulty (RLP)

constexpr db::MapConfig kBlockReceipts{"Receipt"};
constexpr db::MapConfig kBloomBitsIndex{"BloomBitsIndex"};
constexpr db::MapConfig kBloomBits{"BloomBits"};
constexpr db::MapConfig kBodiesSnapshotInfo{"BodiesSnapshotInfo"};
constexpr db::MapConfig kCallFromIndex{"CallFromIndex"};
constexpr db::MapConfig kCallToIndex{"CallToIndex"};
constexpr db::MapConfig kCallTraceSet{"CallTraceSet", ::mdbx::key_mode::usual, ::mdbx::value_mode::multi};
constexpr db::MapConfig kClique{"Clique"};
constexpr db::MapConfig kCode{"Code"};
constexpr db::MapConfig kConfig{"Config"};
constexpr db::MapConfig kContractCode{"HashedCodeHash"};
constexpr db::MapConfig kDatabaseInfo{"DbInfo"};
constexpr db::MapConfig kEthTx{"BlockTransaction"};
constexpr db::MapConfig kHashedAccounts{"HashedAccount"};
constexpr db::MapConfig kHashedStorage{"HashedStorage", ::mdbx::key_mode::usual, ::mdbx::value_mode::multi};
constexpr db::MapConfig kHeadBlock{"LastBlock"};
constexpr db::MapConfig kHeadHeader{"LastHeader"};
constexpr db::MapConfig kHeaderNumbers{"HeaderNumber"};
constexpr db::MapConfig kHeadersSnapshotInfo{"HeadersSnapshotInfo"};
constexpr db::MapConfig kIncarnationMap{"IncarnationMap"};
constexpr db::MapConfig kLogAddressIndex{"LogAddressIndex"};
constexpr db::MapConfig kLogTopicIndex{"LogTopicIndex"};
constexpr db::MapConfig kLogs{"TransactionLog"};
constexpr db::MapConfig kMigrations{"Migration"};
constexpr db::MapConfig kPlainAccountChangeSet{"AccountChangeSet", ::mdbx::key_mode::usual, ::mdbx::value_mode::multi};
constexpr db::MapConfig kPlainContractCode{"PlainCodeHash"};
constexpr db::MapConfig kPlainState{"PlainState", ::mdbx::key_mode::usual, ::mdbx::value_mode::multi};
constexpr db::MapConfig kPlainStorageChangeSet{"StorageChangeSet", ::mdbx::key_mode::usual, ::mdbx::value_mode::multi};
constexpr db::MapConfig kSenders{"TxSender"};
constexpr db::MapConfig kSequence{"Sequence"};
constexpr db::MapConfig kSnapshotInfo{"SnapshotInfo"};
constexpr db::MapConfig kStateSnapshotInfo{"StateSnapshotInfo"};
constexpr db::MapConfig kStorageHistory{"StorageHistory"};
constexpr db::MapConfig kSyncStageProgress{"SyncStage"};      // Progresss for stages
constexpr db::MapConfig kSyncStageUnwind{"SyncStageUnwind"};  // Unwind point for stages
constexpr db::MapConfig kTrieOfAccounts{"TrieAccount"};
constexpr db::MapConfig kTrieOfStorage{"TrieStorage"};
constexpr db::MapConfig kTxLookup{"BlockTransactionLookup"};

constexpr db::MapConfig kTables[]{
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
    kClique,
    kCode,
    kConfig,
    kContractCode,
    kDatabaseInfo,
    kEthTx,
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
    kPlainAccountChangeSet,
    kPlainContractCode,
    kPlainState,
    kPlainStorageChangeSet,
    kSenders,
    kSequence,
    kSnapshotInfo,
    kStateSnapshotInfo,
    kStorageHistory,
    kSyncStageProgress,
    kSyncStageUnwind,
    kTrieOfAccounts,
    kTrieOfStorage,
    kTxLookup,
};

// Create all tables that do not yet exist.
void create_all(mdbx::txn& txn);

// Gets table config given its name
std::optional<db::MapConfig> get_config(std::string name);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_HPP_
