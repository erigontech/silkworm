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

#ifndef SILKWORM_STATE_WRITER_H_
#define SILKWORM_STATE_WRITER_H_

#include <evmc/evmc.hpp>
#include <map>
#include <optional>
#include <set>
#include <silkworm/db/change.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm::state {
class Writer {
 public:
  Writer(const Writer&) = delete;
  Writer& operator=(const Writer&) = delete;

  Writer() = default;

  void write_account(const evmc::address& address, std::optional<Account> initial,
                     std::optional<Account> current);

  void write_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                     const evmc::bytes32& initial, const evmc::bytes32& current);

  const db::AccountChanges& account_changes() const { return account_changes_; }
  const db::StorageChanges& storage_changes() const { return storage_changes_; }

 private:
  db::AccountChanges account_changes_;
  db::StorageChanges storage_changes_;
  std::set<evmc::address> changed_storage_;
};
}  // namespace silkworm::state

#endif  // SILKWORM_STATE_WRITER_H_
