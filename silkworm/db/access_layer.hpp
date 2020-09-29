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

#ifndef SILKWORM_DB_ACCESS_LAYER_H_
#define SILKWORM_DB_ACCESS_LAYER_H_

// Database Access Layer

#include <optional>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/change.hpp>
#include <silkworm/types/block.hpp>
#include <vector>

namespace silkworm::db {

std::optional<BlockWithHash> get_block(lmdb::Transaction& txn, uint64_t block_number);

std::vector<evmc::address> get_senders(lmdb::Transaction& txn, int64_t block_number, const evmc::bytes32& block_hash);

std::optional<AccountChanges> get_account_changes(lmdb::Transaction& txn, uint64_t block_number);

Bytes get_storage_changes(lmdb::Transaction& txn, uint64_t block_number);

}  // namespace silkworm::db

#endif  // SILKWORM_DB_ACCESS_LAYER_H_
