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
constexpr lmdb::TableConfig kAccountHistory{"hAT"};
constexpr lmdb::TableConfig kBlockBodies{"b"};

constexpr lmdb::TableConfig kHeadersHash{"canonical_headers", 0,
                                         lmdb::cmp_fixed_len_key};  // block_num_u64 (BE) -> header_hash
constexpr lmdb::TableConfig kHeadersRlp{"headers", 0,
                                        lmdb::cmp_fixed_len_key};  // block_num_u64 (BE) + hash -> header (RLP)
constexpr lmdb::TableConfig kHeadersDifficulty{
    "header_to_td", 0, lmdb::cmp_fixed_len_key};  // block_num_u64 (BE) + hash -> total_difficulty (RLP)

constexpr lmdb::TableConfig kBlockReceipts{"r"};
constexpr lmdb::TableConfig kBloomBitsIndex{"iB"};
constexpr lmdb::TableConfig kBloomBits{"B"};
constexpr lmdb::TableConfig kBodiesSnapshotInfo{"bSNINFO"};
constexpr lmdb::TableConfig kCallFromIndex{"call_from_index"};
constexpr lmdb::TableConfig kCallToIndex{"call_to_index"};
constexpr lmdb::TableConfig kClique{"clique-"};
constexpr lmdb::TableConfig kCode{"CODE"};
constexpr lmdb::TableConfig kConfig{"ethereum-config-"};
constexpr lmdb::TableConfig kContractCode{"contractCode"};
constexpr lmdb::TableConfig kDatabaseInfo{"DBINFO"};
constexpr lmdb::TableConfig kDatabaseVersion{"DatabaseVersion"};
constexpr lmdb::TableConfig kEthTx{"eth_tx"};
constexpr lmdb::TableConfig kFastTrieProgress{"TrieSync"};
constexpr lmdb::TableConfig kHashedAccounts{"hashed_accounts"};
constexpr lmdb::TableConfig kHashedStorage{"hashed_storage", MDB_DUPSORT};
constexpr lmdb::TableConfig kHeadBlock{"LastBlock"};
constexpr lmdb::TableConfig kHeadFastBlock{"LastFast"};
constexpr lmdb::TableConfig kHeadHeader{"LastHeader"};
constexpr lmdb::TableConfig kHeaderNumbers{"H"};
constexpr lmdb::TableConfig kHeadersSnapshotInfo{"hSNINFO"};
constexpr lmdb::TableConfig kIncarnationMap{"incarnationMap"};
constexpr lmdb::TableConfig kLogAddressIndex{"log_address_index"};
constexpr lmdb::TableConfig kLogTopicIndex{"log_topic_index"};
constexpr lmdb::TableConfig kLogs{"log"};
constexpr lmdb::TableConfig kMigrations{"migrations"};
constexpr lmdb::TableConfig kPlainAccountChangeSet{"PLAIN-ACS", MDB_DUPSORT};
constexpr lmdb::TableConfig kPlainContractCode{"PLAIN-contractCode"};
constexpr lmdb::TableConfig kPlainState{"PLAIN-CST2", MDB_DUPSORT};
constexpr lmdb::TableConfig kPlainStorageChangeSet{"PLAIN-SCS", MDB_DUPSORT};
constexpr lmdb::TableConfig kPreimage{"secure-key-"};
constexpr lmdb::TableConfig kSenders{"txSenders"};
constexpr lmdb::TableConfig kSequence{"sequence"};
constexpr lmdb::TableConfig kSnapshotInfo{"SNINFO"};
constexpr lmdb::TableConfig kStateSnapshotInfo{"sSNINFO"};
constexpr lmdb::TableConfig kStorageHistory{"hST"};
constexpr lmdb::TableConfig kSyncStageProgress{"SSP2"};
constexpr lmdb::TableConfig kSyncStageUnwind{"SSU2"};
constexpr lmdb::TableConfig kTrieOfAccounts{"trie_account"};
constexpr lmdb::TableConfig kTrieOfStorage{"trie_storage"};
constexpr lmdb::TableConfig kTxLookup{"l"};

constexpr lmdb::TableConfig kTables[]{
    kAccountHistory,
    kBlockBodies,
    kBlockReceipts,
    kBloomBits,
    kBloomBitsIndex,
    kBodiesSnapshotInfo,
    kCallFromIndex,
    kCallToIndex,
    kHeadersHash,
    kHeadersRlp,
    kHeadersDifficulty,
    kClique,
    kCode,
    kConfig,
    kContractCode,
    kDatabaseInfo,
    kDatabaseVersion,
    kEthTx,
    kFastTrieProgress,
    kHashedAccounts,
    kHashedStorage,
    kHeadBlock,
    kHeadFastBlock,
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
    kPreimage,
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
