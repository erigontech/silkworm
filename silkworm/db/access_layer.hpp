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

#include <optional>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/types/block.hpp>
#include <vector>

// Database Access Layer
namespace silkworm::dal {

std::optional<BlockWithHash> get_block(lmdb::Transaction& txn, uint64_t block_number);

std::vector<evmc::address> get_senders(lmdb::Transaction& txn, int64_t block_number, const evmc::bytes32& block_hash);

}  // namespace silkworm::dal

#endif  // SILKWORM_DB_ACCESS_LAYER_H_
