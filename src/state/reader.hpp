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

#ifndef SILKWORM_STATE_READER_H_
#define SILKWORM_STATE_READER_H_

#include <stdint.h>

#include <optional>
#include <string>

#include "db/database.hpp"
#include "types/account.hpp"

namespace silkworm::state {
class Reader {
 public:
  Reader(const Reader&) = delete;
  Reader& operator=(const Reader&) = delete;

  Reader() = default;
  // explicit Reader(db::Database& db) : db_{db} {}

  std::optional<Account> read_account(const evmc::address& address) const;
  std::string read_account_code(const evmc::address& address) const;
  evmc::bytes32 read_account_storage(const evmc::address& address, uint64_t incarnation,
                                     const evmc::bytes32& key) const;

 private:
  // db::Database& db_;
};
}  // namespace silkworm::state

#endif  // SILKWORM_STATE_READER_H_
