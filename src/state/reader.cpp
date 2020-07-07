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

#include "reader.hpp"

#include "common/util.hpp"
#include "db/bucket.hpp"

namespace silkworm::state {

std::optional<Account> Reader::read_account(const evmc::address& address) const {
  std::optional<std::string> encoded = get(address_as_string_view(address));
  if (!encoded) return {};

  return decode_account_from_storage(*encoded);
}

std::string Reader::read_account_code(const evmc::address&) const {
  // TODO(Andrew) implement
  return "";
}

evmc::bytes32 Reader::read_account_storage(const evmc::address&, uint64_t,
                                           const evmc::bytes32&) const {
  // TODO(Andrew) implement
  return {};
}

std::optional<std::string> Reader::get(std::string_view key) const {
  std::unique_ptr<db::Transaction> txn = db_.begin_ro_transaction();
  // TODO(Andrew) historic data
  std::unique_ptr<db::Bucket> bucket = txn->get_bucket(db::bucket::kPlainState);
  std::optional<std::string_view> val = bucket->get(key);
  return val ? std::string{*val} : nullptr;
}
}  // namespace silkworm::state
