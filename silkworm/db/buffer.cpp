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

void Buffer::begin_new_block(uint64_t block_number) {
    current_block_number_ = block_number;
    changed_storage_.clear();
}

void Buffer::update_account(const evmc::address& address, std::optional<Account> initial,
                            std::optional<Account> current) {
    bool equal{current == initial};
    bool account_deleted{!current};

    if (equal && !account_deleted && !changed_storage_.contains(address)) {
        // Follows the Turbo-Geth logic when to populate account changes.
        // See (ChangeSetWriter)UpdateAccountData & DeleteAccount.
        return;
    }

    if (initial) {
        bool omit_code_hash{!account_deleted};
        account_changes_[current_block_number_][address] = initial->encode_for_storage(omit_code_hash);
    } else {
        account_changes_[current_block_number_][address] = {};
    }

    if (equal) {
        return;
    }

    accounts_[address] = current;

    if (account_deleted && initial->incarnation) {
        incarnations_[address] = initial->incarnation;
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
    storage_changes_[current_block_number_][full_key] = zeroless_view(initial);
    storage_[storage_prefix(address, incarnation)][key] = current;
}

void Buffer::write_to_db() {
    if (!txn_) {
        return;
    }

    auto state_table{txn_->open(table::kPlainState)};
    for (const auto& entry : accounts_) {
        state_table->del(full_view(entry.first));
        if (entry.second) {
            bool omit_code_hash{false};
            Bytes encoded{entry.second->encode_for_storage(omit_code_hash)};
            state_table->put(full_view(entry.first), encoded);
        }
    }
    for (const auto& contract : storage_) {
        for (const auto& x : contract.second) {
            state_table->del(contract.first, full_view(x.first));
            if (!is_zero(x.second)) {
                Bytes data{full_view(x.first)};
                data.append(zeroless_view(x.second));
                state_table->put(contract.first, data);
            }
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
    for (const auto& entry : account_changes_) {
        Bytes block_key{encode_timestamp(entry.first)};
        account_change_table->put(block_key, entry.second.encode());
    }

    auto storage_change_table{txn_->open(table::kStorageChanges)};
    for (const auto& entry : storage_changes_) {
        Bytes block_key{encode_timestamp(entry.first)};
        storage_change_table->put(block_key, entry.second.encode());
    }
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
    if (auto it{headers_.find(key)}; it != headers_.end()) {
        return it->second;
    }
    if (!txn_) {
        return std::nullopt;
    }
    return db::read_header(*txn_, block_number, block_hash);
}

std::optional<Account> Buffer::read_account(const evmc::address& address) const noexcept {
    if (auto it{accounts_.find(address)}; it != accounts_.end()) {
        return it->second;
    }
    if (!txn_) {
        return std::nullopt;
    }
    return db::read_account(*txn_, address, historical_block_);
}

Bytes Buffer::read_code(const evmc::bytes32& code_hash) const noexcept {
    if (auto it{hash_to_code_.find(code_hash)}; it != hash_to_code_.end()) {
        return it->second;
    }
    if (!txn_) {
        return {};
    }
    std::optional<Bytes> code{db::read_code(*txn_, code_hash)};
    if (code) {
        return *code;
    } else {
        return {};
    }
}

evmc::bytes32 Buffer::read_storage(const evmc::address& address, uint64_t incarnation,
                                   const evmc::bytes32& key) const noexcept {
    if (auto it{storage_.find(storage_prefix(address, incarnation))}; it != storage_.end()) {
        if (auto it2{it->second.find(key)}; it2 != it->second.end()) {
            return it2->second;
        }
    }
    if (!txn_) {
        return {};
    }
    return db::read_storage(*txn_, address, incarnation, key, historical_block_);
}

uint64_t Buffer::previous_incarnation(const evmc::address& address) const noexcept {
    if (auto it{incarnations_.find(address)}; it != incarnations_.end()) {
        return it->second;
    }
    if (!txn_) {
        return 0;
    }
    std::optional<uint64_t> incarnation{db::read_previous_incarnation(*txn_, address, historical_block_)};
    return incarnation ? *incarnation : 0;
}

}  // namespace silkworm::db
