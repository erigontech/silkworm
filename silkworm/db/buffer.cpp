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

// See TG mutation_puts.go
static constexpr size_t kEntryOverhead{32};

void Buffer::begin_new_block(uint64_t block_number) {
    current_block_number_ = block_number;
    changed_storage_.clear();

    // some rather arbitrary fixed overhead of account & storage changes
    batch_size_ += 4 * kEntryOverhead;
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

    Bytes encoded_initial{};
    if (initial) {
        bool omit_code_hash{!account_deleted};
        encoded_initial = initial->encode_for_storage(omit_code_hash);
    }
    if (account_changes_[current_block_number_].insert_or_assign(address, encoded_initial).second) {
        batch_size_ += kAddressLength + encoded_initial.length();
    }

    if (equal) {
        return;
    }

    if (accounts_.insert_or_assign(address, current).second) {
        batch_size_ += kAddressLength + kEntryOverhead;
        if (current) {
            batch_size_ += current->encoding_length_for_storage();
        };
    };

    if (account_deleted && initial->incarnation) {
        if (incarnations_.insert_or_assign(address, initial->incarnation).second) {
            batch_size_ += kStoragePrefixLength + kEntryOverhead;
        }
    }
}

void Buffer::update_account_code(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& code_hash,
                                 ByteView code) {
    if (hash_to_code_.insert_or_assign(code_hash, code).second) {
        batch_size_ += kHashLength + kEntryOverhead + code.length();
    }
    if (storage_prefix_to_code_hash_.insert_or_assign(storage_prefix(address, incarnation), code_hash).second) {
        batch_size_ += kStoragePrefixLength + kEntryOverhead + kHashLength;
    }
}

void Buffer::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& key,
                            const evmc::bytes32& initial, const evmc::bytes32& current) {
    if (current == initial) {
        return;
    }
    changed_storage_.insert(address);
    Bytes full_key{storage_key(address, incarnation, key)};
    ByteView compact_initial{zeroless_view(initial)};
    if (storage_changes_[current_block_number_].insert_or_assign(full_key, compact_initial).second) {
        batch_size_ += kStoragePrefixLength + kHashLength + compact_initial.length();
    }

    auto& storage_map{storage_[address][incarnation]};
    if (storage_map.empty()) {
        batch_size_ += kStoragePrefixLength;
    }
    if (storage_map.insert_or_assign(key, current).second) {
        batch_size_ += kEntryOverhead + kHashLength + zeroless_view(current).size();
    }
}

static void upsert_storage_value(lmdb::Table& state_table, ByteView storage_prefix, const evmc::bytes32& key,
                                 const evmc::bytes32& value) {
    state_table.del(storage_prefix, full_view(key));
    if (!is_zero(value)) {
        Bytes data{full_view(key)};
        data.append(zeroless_view(value));
        state_table.put(storage_prefix, data);
    }
}

void Buffer::write_to_state_table() {
    auto state_table{txn_->open(table::kPlainState)};

    std::set<evmc::address> keys;
    for (auto& x : accounts_) {
        keys.insert(x.first);
    }
    for (auto& x : storage_) {
        keys.insert(x.first);
    }

    for (const auto& key : keys) {
        if (auto it{accounts_.find(key)}; it != accounts_.end()) {
            state_table->del(full_view(key));
            if (it->second.has_value()) {
                bool omit_code_hash{false};
                Bytes encoded{it->second->encode_for_storage(omit_code_hash)};
                state_table->put(full_view(key), encoded);
            }
        }

        if (auto it{storage_.find(key)}; it != storage_.end()) {
            for (const auto& contract : it->second) {
                uint64_t incarnation{contract.first};
                Bytes prefix{storage_prefix(it->first, incarnation)};
                for (const auto& x : contract.second) {
                    upsert_storage_value(*state_table, prefix, x.first, x.second);
                }
            }
        }
    }
}

void Buffer::write_to_db() {
    if (!txn_) {
        return;
    }

    write_to_state_table();

    auto incarnation_table{txn_->open(table::kIncarnationMap)};
    for (const auto& entry : incarnations_) {
        Bytes buf(kIncarnationLength, '\0');
        boost::endian::store_big_u64(&buf[0], entry.second);
        incarnation_table->put(full_view(entry.first), buf);
    }

    auto code_table{txn_->open(table::kCode)};
    for (const auto& entry : hash_to_code_) {
        code_table->put(full_view(entry.first), entry.second);
    }

    auto code_hash_table{txn_->open(table::kPlainContractCode)};
    for (const auto& entry : storage_prefix_to_code_hash_) {
        code_hash_table->put(entry.first, full_view(entry.second));
    }

    auto account_change_table{txn_->open(table::kPlainAccountChangeSet)};
    for (const auto& entry : account_changes_) {
        Bytes block_key{encode_timestamp(entry.first)};
        account_change_table->put(block_key, entry.second.encode());
    }

    auto storage_change_table{txn_->open(table::kPlainStorageChangeSet)};
    for (const auto& entry : storage_changes_) {
        Bytes block_key{encode_timestamp(entry.first)};
        storage_change_table->put(block_key, entry.second.encode());
    }

    auto receipt_table{txn_->open(table::kBlockReceipts)};
    for (const auto& entry : receipts_) {
        receipt_table->put(entry.first, entry.second);
    }
}

void Buffer::insert_receipts(const Bytes& key, const Bytes& value) {
    if (receipts_.insert_or_assign(key, value).second) {
        batch_size_ += key.size() + kEntryOverhead + value.size();
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
    if (auto it1{storage_.find(address)}; it1 != storage_.end()) {
        if (auto it2{it1->second.find(incarnation)}; it2 != it1->second.end()) {
            if (auto it3{it2->second.find(key)}; it3 != it2->second.end()) {
                return it3->second;
            }
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
