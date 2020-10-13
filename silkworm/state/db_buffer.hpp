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

#ifndef SILKWORM_STATE_DB_BUFFER_H_
#define SILKWORM_STATE_DB_BUFFER_H_

#include <absl/container/flat_hash_set.h>

#include <evmc/evmc.hpp>
#include <map>
#include <optional>
#include <silkworm/db/chaindb.hpp>
#include <silkworm/db/change.hpp>
#include <silkworm/types/account.hpp>

namespace silkworm {

class DbBuffer {
   public:
    DbBuffer(const DbBuffer&) = delete;
    DbBuffer& operator=(const DbBuffer&) = delete;

    DbBuffer() = default;

    void update_account(const evmc::address& address, std::optional<Account> initial, std::optional<Account> current);

    void update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                             ByteView code);

    void update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                        const evmc::bytes32& initial, const evmc::bytes32& current);

    void write_to_db(lmdb::Transaction& txn, uint64_t block_number);

    const db::AccountChanges& account_back_changes() const { return account_back_changes_; }
    const db::StorageChanges& storage_back_changes() const { return storage_back_changes_; }

   private:
    db::AccountChanges account_back_changes_;
    db::StorageChanges storage_back_changes_;
    db::AccountChanges account_forward_changes_;
    db::StorageChanges storage_forward_changes_;
    absl::flat_hash_set<evmc::address> changed_storage_;
    std::map<evmc::address, uint64_t> incarnations_of_deleted_contracts_;
    std::map<evmc::bytes32, Bytes> hash_to_code_;
    std::map<Bytes, evmc::bytes32> storage_prefix_to_code_hash_;
};

}  // namespace silkworm

#endif  // SILKWORM_STATE_DB_BUFFER_H_
