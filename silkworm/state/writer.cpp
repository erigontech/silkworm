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

#include <boost/endian/conversion.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/util.hpp>

namespace silkworm::state {

void Writer::update_account(const evmc::address& address, std::optional<Account> initial,
                            std::optional<Account> current) {
    bool equal{current == initial};
    bool account_deleted{!current};

    if (equal && !account_deleted && !changed_storage_.contains(address)) {
        // Follow Turbo-Geth logic when to populate account_back_changes
        // See (ChangeSetWriter)UpdateAccountData & DeleteAccount
        return;
    }

    if (initial) {
        bool omit_code_hash{!account_deleted};
        account_back_changes_[address] = initial->encode_for_storage(omit_code_hash);
    } else {
        account_back_changes_[address] = {};
    }

    if (equal) {
        return;
    }

    if (current) {
        bool omit_code_hash{false};
        account_forward_changes_[address] = current->encode_for_storage(omit_code_hash);
    } else {
        account_forward_changes_[address] = {};
        if (initial->incarnation) {
            incarnations_of_deleted_contracts_[address] = initial->incarnation;
        }
    }
}

void Writer::update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                                 ByteView code) {
    hash_to_code_[code_hash] = code;
    storage_prefix_to_code_hash_[db::storage_prefix(address, incarnation)] = code_hash;
}

void Writer::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                            const evmc::bytes32& initial, const evmc::bytes32& current) {
    if (current == initial) {
        return;
    }
    changed_storage_.insert(address);
    Bytes storage_key{db::storage_key(address, incarnation, key)};
    storage_back_changes_[storage_key] = zeroless_view(initial);
    storage_forward_changes_[storage_key] = zeroless_view(current);
}

void Writer::write_to_db(lmdb::Transaction& txn) {
    auto state_table{txn.open(db::table::kPlainState)};
    for (const auto& entry : account_forward_changes_) {
        if (entry.second.empty()) {
            state_table->del(full_view(entry.first));
        } else {
            state_table->put(full_view(entry.first), entry.second);
        }
    }
    for (const auto& entry : storage_forward_changes_) {
        Bytes key{entry.first.substr(0, db::kStoragePrefixSize)};
        Bytes x{entry.first.substr(db::kStoragePrefixSize)};
        state_table->del(key, x);
        if (!entry.second.empty()) {
            x += entry.second;
            state_table->put(key, x);
        }
    }

    auto incarnation_table{txn.open(db::table::kIncarnations)};
    for (const auto& entry : incarnations_of_deleted_contracts_) {
        Bytes buf(db::kIncarnationLength, '\0');
        boost::endian::store_big_u64(&buf[0], entry.second);
        incarnation_table->put(full_view(entry.first), buf);
    }

    auto code_table{txn.open(db::table::kCode)};
    for (const auto& entry : hash_to_code_) {
        code_table->put(full_view(entry.first), entry.second);
    }

    auto code_hash_table{txn.open(db::table::kCodeHash)};
    for (const auto& entry : storage_prefix_to_code_hash_) {
        code_hash_table->put(entry.first, full_view(entry.second));
    }

    // TODO(Andrew) kAccountChanges, kStorageChanges
}

}  // namespace silkworm::state
