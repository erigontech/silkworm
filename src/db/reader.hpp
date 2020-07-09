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

#ifndef SILKWORM_DB_READER_H_
#define SILKWORM_DB_READER_H_

#include <optional>

#include "database.hpp"
#include "state/change_set.hpp"
#include "types/block.hpp"

namespace silkworm::db {
std::optional<Block> get_block(Database& db, uint64_t block_number);
std::optional<AccountChanges> get_account_changes(Database& db, uint64_t block_number);
}  // namespace silkworm::db

#endif  // SILKWORM_DB_READER_H_
