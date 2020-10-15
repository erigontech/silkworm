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

#ifndef SILKWORM_DB_TABLES_H_
#define SILKWORM_DB_TABLES_H_

#include <silkworm/db/chaindb.hpp>

/*
Part of the compatibility layer with the Turbo-Geth DB format;
see its common/dbutils/bucket.go.
*/
namespace silkworm::db::table {

/* Canonical tables */
constexpr lmdb::TableConfig kPlainState{"PLAIN-CST2", MDB_DUPSORT};
constexpr lmdb::TableConfig kPlainContractCode{"PLAIN-contractCode"};
constexpr lmdb::TableConfig kPlainAccountChangeSet{"PLAIN-ACS"};
constexpr lmdb::TableConfig kPlainStorageChangeSet{"PLAIN-SCS"};
constexpr lmdb::TableConfig kCurrentState{"CST2", MDB_DUPSORT};
constexpr lmdb::TableConfig kAccountHistory{"hAT"};
constexpr lmdb::TableConfig kStorageHistory{"hST"};
constexpr lmdb::TableConfig kCode{"CODE"};
constexpr lmdb::TableConfig kContractCode{"contractCode"};
constexpr lmdb::TableConfig kIncarnationMap{"incarnationMap"};
constexpr lmdb::TableConfig kAccountChangeSet{"ACS"};
constexpr lmdb::TableConfig kStorageChangeSet{"SCS"};
constexpr lmdb::TableConfig kIntermediateTrieHash{"iTh2", MDB_DUPSORT};
constexpr lmdb::TableConfig kDatabaseInfo{"DBINFO"};
constexpr lmdb::TableConfig kDatabaseVersion{"DatabaseVersion"};
constexpr lmdb::TableConfig kBlockHeaders{"h"};
constexpr lmdb::TableConfig kBlockBodies{"b"};
constexpr lmdb::TableConfig kBlockReceipts{"r"};
constexpr lmdb::TableConfig kLogTopicIndex{"log_topic_index"};
constexpr lmdb::TableConfig kLogAddressIndex{"log_address_index"};
constexpr lmdb::TableConfig kTxLookup{"l"};
constexpr lmdb::TableConfig kBloomBits{"B"};
constexpr lmdb::TableConfig kBloomBitsIndex{"iB"};
constexpr lmdb::TableConfig kPreimage{"secure-key-"};
constexpr lmdb::TableConfig kConfig{"ethereum-config-"};
constexpr lmdb::TableConfig kSyncStageProgress{"SSP2"};
constexpr lmdb::TableConfig kSyncStageUnwind{"SSU2"};
constexpr lmdb::TableConfig kClique{"clique-"};
constexpr lmdb::TableConfig kSenders{"txSenders"};
constexpr lmdb::TableConfig kMigrations{"migrations"};
constexpr lmdb::TableConfig kFastTrieProgress{"TrieSync"};
constexpr lmdb::TableConfig kHeadBlock{"LastBlock"};
constexpr lmdb::TableConfig kHeadFastBlock{"LastFast"};
constexpr lmdb::TableConfig kHeadHeader{"LastHeader"};

/* Deprecated Tables */
constexpr lmdb::TableConfig kPlainStateOld1{"PLAIN-CST", MDB_DUPSORT};
constexpr lmdb::TableConfig kCurrentStateOld1{"CST"};
constexpr lmdb::TableConfig kSyncStageProgressOld1{"SSP"};
constexpr lmdb::TableConfig kSyncStageUnwindOld1{"SSU"};
constexpr lmdb::TableConfig kIntermediateTrieHashOld1{"iTh"};

constexpr lmdb::TableConfig kTables[]{kPlainState,
                                      kPlainContractCode,
                                      kPlainAccountChangeSet,
                                      kPlainStorageChangeSet,
                                      kCurrentState,
                                      kAccountHistory,
                                      kStorageHistory,
                                      kCode,
                                      kBlockHeaders,
                                      kBlockBodies,
                                      kBlockReceipts,
                                      kSenders,
                                      kIncarnationMap,
                                      kAccountChangeSet,
                                      kStorageChangeSet,
                                      kIntermediateTrieHash,
                                      kDatabaseInfo,
                                      kDatabaseVersion,
                                      kLogTopicIndex,
                                      kLogAddressIndex,
                                      kTxLookup,
                                      kBloomBits,
                                      kBloomBitsIndex,
                                      kPreimage,
                                      kConfig,
                                      kSyncStageProgress,
                                      kSyncStageUnwind,
                                      kClique,
                                      kMigrations,
                                      kFastTrieProgress,
                                      kHeadBlock,
                                      kHeadFastBlock,
                                      kHeadHeader};

constexpr lmdb::TableConfig kDeprecatedTables[]{kPlainStateOld1, kCurrentStateOld1, kSyncStageProgressOld1,
                                                kSyncStageUnwindOld1, kIntermediateTrieHashOld1};

// Create all tables that do not yet exist.
void create_all(lmdb::Transaction& txn);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_H_
