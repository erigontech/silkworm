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

constexpr lmdb::TableConfig kPlainState{"PLAIN-CST2", /*dupsort=*/true};
constexpr lmdb::TableConfig kAccountChanges{"PLAIN-ACS"};
constexpr lmdb::TableConfig kStorageChanges{"PLAIN-SCS"};
constexpr lmdb::TableConfig kAccountHistory{"hAT"};
constexpr lmdb::TableConfig kStorageHistory{"hST"};
constexpr lmdb::TableConfig kCode{"CODE"};
constexpr lmdb::TableConfig kCodeHash{"PLAIN-contractCode"};
constexpr lmdb::TableConfig kBlockHeaders{"h"};
constexpr lmdb::TableConfig kBlockBodies{"b"};
constexpr lmdb::TableConfig kSenders{"txSenders"};

constexpr lmdb::TableConfig kTables[]{kPlainState, kAccountChanges, kStorageChanges, kAccountHistory, kStorageHistory,
                                      kCode,       kCodeHash,       kBlockHeaders,   kBlockBodies,    kSenders};

// Create all tables that do not yet exist.
void create_all(lmdb::Transaction& txn);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_H_
