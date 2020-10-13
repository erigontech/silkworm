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

#include "buffer.hpp"

#include <boost/endian/conversion.hpp>
#include <silkworm/common/util.hpp>

#include "access_layer.hpp"
#include "tables.hpp"
#include "util.hpp"

namespace silkworm::db {

void Buffer::update_account(const evmc::address& address, std::optional<Account> initial,
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
            incarnations_[address] = initial->incarnation;
        }
    }
}

void Buffer::update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                                 ByteView code) {
    hash_to_code_[code_hash] = code;
    storage_prefix_to_code_hash_[storage_prefix(address, incarnation)] = code_hash;
}

void Buffer::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                            const evmc::bytes32& initial, const evmc::bytes32& current) {
    if (current == initial) {
        return;
    }
    changed_storage_.insert(address);
    Bytes full_key{storage_key(address, incarnation, key)};
    storage_back_changes_[full_key] = zeroless_view(initial);
    storage_forward_changes_[full_key] = zeroless_view(current);
}

void Buffer::write_to_db(uint64_t block_number) {
    if (!txn_) {
        return;
    }

    auto state_table{txn_->open(table::kPlainState)};
    for (const auto& entry : account_forward_changes_) {
        state_table->del(full_view(entry.first));
        if (!entry.second.empty()) {
            state_table->put(full_view(entry.first), entry.second);
        }
    }
    for (const auto& entry : storage_forward_changes_) {
        Bytes key{entry.first.substr(0, kStoragePrefixLength)};
        Bytes x{entry.first.substr(kStoragePrefixLength)};
        state_table->del(key, x);
        if (!entry.second.empty()) {
            x += entry.second;
            state_table->put(key, x);
        }
    }

    auto incarnation_table{txn_->open(table::kIncarnations)};
    for (const auto& entry : incarnations_) {
        Bytes buf(kIncarnationLength, '\0');
        boost::endian::store_big_u64(&buf[0], entry.second);
        incarnation_table->put(full_view(entry.first), buf);
    }

    auto code_table{txn_->open(table::kCode)};
    for (const auto& entry : hash_to_code_) {
        code_table->put(full_view(entry.first), entry.second);
    }

    auto code_hash_table{txn_->open(table::kCodeHash)};
    for (const auto& entry : storage_prefix_to_code_hash_) {
        code_hash_table->put(entry.first, full_view(entry.second));
    }

    auto account_change_table{txn_->open(table::kAccountChanges)};
    Bytes block_key{encode_timestamp(block_number)};
    account_change_table->put(block_key, account_back_changes_.encode());

    auto storage_change_table{txn_->open(table::kStorageChanges)};
    storage_change_table->put(block_key, storage_back_changes_.encode());
}

void Buffer::insert_header(BlockHeader block_header) {
    Bytes rlp{};
    rlp::encode(rlp, block_header);
    ethash::hash256 hash{keccak256(rlp)};
    Bytes key{block_key(block_header.number, hash.bytes)};
    headers_[key] = std::move(block_header);
}

std::optional<BlockHeader> Buffer::read_header(uint64_t block_number, const evmc::bytes32& block_hash) const noexcept {
    Bytes key{block_key(block_number, block_hash.bytes)};
    auto it{headers_.find(key)};
    if (it != headers_.end()) {
        return it->second;
    }

    if (txn_) {
        return db::read_header(*txn_, block_number, block_hash);
    } else {
        return std::nullopt;
    }
}

}  // namespace silkworm::db
