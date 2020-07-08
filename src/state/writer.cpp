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

#include "common/util.hpp"
#include "db/util.hpp"

namespace silkworm::state {

void Writer::write_account(const evmc::address& address, std::optional<Account> original,
                           std::optional<Account> committed) {
  if (original == committed && changed_storage_.count(address) == 0) return;

  if (original) {
    account_changes_[address] = original->encode_for_storage();
  } else {
    account_changes_[address] = {};
  }
}

void Writer::write_storage(const evmc::address& address, uint64_t incarnation,
                           const evmc::bytes32& key, const evmc::bytes32& original,
                           const evmc::bytes32& committed) {
  if (committed == original) return;
  changed_storage_.insert(address);
  std::string storage_key{db::storage_key(address, incarnation, key)};
  storage_changes_[storage_key] = hash_as_string_view(original);
}

}  // namespace silkworm::state
