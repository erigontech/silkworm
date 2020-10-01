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

constexpr const char* kPlainState{"PLAIN-CST"};
constexpr const char* kAccountChanges{"PLAIN-ACS"};
constexpr const char* kStorageChanges{"PLAIN-SCS"};
constexpr const char* kAccountHistory{"hAT"};
constexpr const char* kStorageHistory{"hST"};
constexpr const char* kCode{"CODE"};
constexpr const char* kCodeHash{"PLAIN-contractCode"};
constexpr const char* kLastBlock{"LastBlock"};
constexpr const char* kLastFast{"LastFast"};
constexpr const char* kLastHeader{"LastHeader"};
constexpr const char* kBlockHeaders{"h"};
constexpr const char* kBlockBodies{"b"};
constexpr const char* kSenders{"txSenders"};

constexpr const char* kTables[]{kPlainState,   kAccountChanges, kStorageChanges, kAccountHistory, kStorageHistory,
                                kCode,         kCodeHash,       kLastBlock,      kLastFast,       kLastHeader,
                                kBlockHeaders, kBlockBodies,    kSenders};

// Create all tables that do not yet exist.
void create_all(lmdb::Transaction& txn);

}  // namespace silkworm::db::table

#endif  // SILKWORM_DB_TABLES_H_
