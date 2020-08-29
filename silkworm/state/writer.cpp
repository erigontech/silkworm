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

#include "writer.hpp"

#include <silkworm/common/util.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::state {

void Writer::write_account(const evmc::address& address, std::optional<Account> initial,
                           std::optional<Account> current) {
  bool account_deleted{!current};

  if (!account_deleted && current == initial && changed_storage_.count(address) == 0) {
    return;
  }

  if (initial) {
    bool omit_code_hash{!account_deleted};
    account_changes_[address] = initial->encode_for_storage(omit_code_hash);
  } else {
    account_changes_[address] = {};
  }
}

void Writer::write_storage(const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& key, const evmc::bytes32& initial,
                           const evmc::bytes32& current) {
  if (current == initial) {
    return;
  }
  changed_storage_.insert(address);
  Bytes storage_key{db::storage_key(address, incarnation, key)};
  storage_changes_[storage_key] = zeroless_view(initial);
}
}  // namespace silkworm::state
