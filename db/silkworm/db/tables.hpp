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

#include <silkworm/db/chaindb.hpp>

/*
Part of the compatibility layer with the Turbo-Geth DB format;
see its common/dbutils/bucket.go.
*/
namespace silkworm::db::table {

/* Canonical tables */
constexpr lmdb::TableConfig kMAIN_DBI{nullptr};
constexpr lmdb::TableConfig kAccountHistory{"AccountHistory"};
constexpr lmdb::TableConfig kBlockBodies{"BlockBody"};

constexpr lmdb::TableConfig kCanonicalHashes{"CanonicalHeader", 0,
                                             lmdb::cmp_fixed_len_key};  // block_num_u64 (BE) -> header_hash
constexpr lmdb::TableConfig kHeaders{"Header", 0,
                                     lmdb::cmp_fixed_len_key};  // block_num_u64 (BE) + hash -> header (RLP)
constexpr lmdb::TableConfig kDifficulty{
    "HeadersTotalDifficulty", 0, lmdb::cmp_fixed_len_key};  // block_num_u64 (BE) + hash -> total_difficulty (RLP)

constexpr lmdb::TableConfig kBlockReceipts{"Receipt"};
constexpr lmdb::TableConfig kBloomBitsIndex{"BloomBitsIndex"};
constexpr lmdb::TableConfig kBloomBits{"BloomBits"};
constexpr lmdb::TableConfig kBodiesSnapshotInfo{"BodiesSnapshotInfo"};
constexpr lmdb::TableConfig kCallFromIndex{"CallFromIndex"};
constexpr lmdb::TableConfig kCallToIndex{"CallToIndex"};
constexpr lmdb::TableConfig kClique{"Clique"};
constexpr lmdb::TableConfig kCode{"Code"};
constexpr lmdb::TableConfig kConfig{"Config"};
constexpr lmdb::TableConfig kContractCode{"HashedCodeHash"};
constexpr lmdb::TableConfig kDatabaseInfo{"DbInfo"};
constexpr lmdb::TableConfig kEthTx{"BlockTransaction"};
constexpr lmdb::TableConfig kHashedAccounts{"HashedAccount"};
constexpr lmdb::TableConfig kHashedStorage{"HashedStorage", MDB_DUPSORT};
constexpr lmdb::TableConfig kHeadBlock{"LastBlock"};
constexpr lmdb::TableConfig kHeadHeader{"LastHeader"};
constexpr lmdb::TableConfig kHeaderNumbers{"HeaderNumber"};
constexpr lmdb::TableConfig kHeadersSnapshotInfo{"HeadersSnapshotInfo"};
constexpr lmdb::TableConfig kIncarnationMap{"IncarnationMap"};
constexpr lmdb::TableConfig kLogAddressIndex{"LogAddressIndex"};
constexpr lmdb::TableConfig kLogTopicIndex{"LogTopicIndex"};
constexpr lmdb::TableConfig kLogs{"TransactionLog"};
constexpr lmdb::TableConfig kMigrations{"Migration"};
constexpr lmdb::TableConfig kPlainAccountChangeSet{"AccountChangeSet", MDB_DUPSORT};
constexpr lmdb::TableConfig kPlainContractCode{"PlainCodeHash"};
constexpr lmdb::TableConfig kPlainState{"PlainState", MDB_DUPSORT};
constexpr lmdb::TableConfig kPlainStorageChangeSet{"StorageChangeSet", MDB_DUPSORT};
constexpr lmdb::TableConfig kSenders{"TxSender"};
constexpr lmdb::TableConfig kSequence{"Sequence"};
constexpr lmdb::TableConfig kSnapshotInfo{"SnapshotInfo"};
constexpr lmdb::TableConfig kStateSnapshotInfo{"StateSnapshotInfo"};
constexpr lmdb::TableConfig kStorageHistory{"StorageHistory"};
constexpr lmdb::TableConfig kSyncStageProgress{"SyncStage"};  // Progresss for stages
constexpr lmdb::TableConfig kSyncStageUnwind{"SyncStageUnwind"};    // Unwind point for stages
constexpr lmdb::TableConfig kTrieOfAccounts{"TrieAccount"};
constexpr lmdb::TableConfig kTrieOfStorage{"TrieStorage"};
constexpr lmdb::TableConfig kTxLookup{"BlockTransactionLookup"};

constexpr lmdb::TableConfig kTables[]{
    kAccountHistory,
    kBlockBodies,
    kBlockReceipts,
    kBloomBits,
    kBloomBitsIndex,
    kBodiesSnapshotInfo,
    kCallFromIndex,
    kCallToIndex,
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
void create_all(lmdb::Transaction& txn);

// Gets table config given its name
std::optional<lmdb::TableConfig> get_config(std::string name);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_HPP_
