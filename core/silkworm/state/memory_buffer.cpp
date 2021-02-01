/*
   Copyright 2020-2021 The Silkworm Authors

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

#include "memory_buffer.hpp"

#include <ethash/keccak.hpp>
#include <map>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/trie/hash_builder.hpp>

namespace silkworm {

std::optional<Account> MemoryBuffer::read_account(const evmc::address& address) const noexcept {
    auto it{accounts_.find(address)};
    if (it == accounts_.end()) {
        return std::nullopt;
    }
    return it->second;
}

Bytes MemoryBuffer::read_code(const evmc::bytes32& code_hash) const noexcept {
    auto it{code_.find(code_hash)};
    if (it == code_.end()) {
        return {};
    }
    return it->second;
}

evmc::bytes32 MemoryBuffer::read_storage(const evmc::address& address, uint64_t incarnation,
                                         const evmc::bytes32& location) const noexcept {
    auto it1{storage_.find(address)};
    if (it1 == storage_.end()) {
        return {};
    }
    auto it2{it1->second.find(incarnation)};
    if (it2 == it1->second.end()) {
        return {};
    }
    auto it3{it2->second.find(location)};
    if (it3 == it2->second.end()) {
        return {};
    }
    return it3->second;
}

uint64_t MemoryBuffer::previous_incarnation(const evmc::address& address) const noexcept {
    auto it{prev_incarnations_.find(address)};
    if (it == prev_incarnations_.end()) {
        return 0;
    }
    return it->second;
}

std::optional<BlockHeader> MemoryBuffer::read_header(uint64_t block_number,
                                                     const evmc::bytes32& block_hash) const noexcept {
    auto it1{headers_.find(block_number)};
    if (it1 == headers_.end()) {
        return std::nullopt;
    }
    auto it2{it1->second.find(block_hash)};
    if (it2 == it1->second.end()) {
        return std::nullopt;
    }
    return it2->second;
}

void MemoryBuffer::insert_header(const BlockHeader& block_header) {
    Bytes rlp;
    rlp::encode(rlp, block_header);
    ethash::hash256 hash{keccak256(rlp)};
    evmc::bytes32 hash_key;
    std::memcpy(hash_key.bytes, hash.bytes, kHashLength);
    headers_[block_header.number][hash_key] = block_header;
}

void MemoryBuffer::insert_receipts(uint64_t, const std::vector<Receipt>&) {}

void MemoryBuffer::begin_block(uint64_t block_number) {
    block_number_ = block_number;
    account_changes_.erase(block_number);
    storage_changes_.erase(block_number);
}

void MemoryBuffer::update_account(const evmc::address& address, std::optional<Account> initial,
                                  std::optional<Account> current) {
    account_changes_[block_number_][address] = initial;

    if (current) {
        accounts_[address] = *current;
    } else {
        accounts_.erase(address);
        if (initial) {
            prev_incarnations_[address] = initial->incarnation;
        }
    }
}

void MemoryBuffer::update_account_code(const evmc::address&, uint64_t, const evmc::bytes32& code_hash, ByteView code) {
    code_[code_hash] = code;
}

void MemoryBuffer::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                                  const evmc::bytes32& initial, const evmc::bytes32& current) {
    storage_changes_[block_number_][address][incarnation][location] = initial;

    if (is_zero(current)) {
        storage_[address][incarnation].erase(location);
    } else {
        storage_[address][incarnation][location] = current;
    }
}

void MemoryBuffer::unwind_block(uint64_t block_number) {
    for (const auto& [address, account] : account_changes_[block_number]) {
        if (account) {
            accounts_[address] = *account;
        } else {
            accounts_.erase(address);
        }
    }

    for (const auto& [address, storage1] : storage_changes_[block_number]) {
        for (const auto& [incarnation, storage2] : storage1) {
            for (const auto& [location, value] : storage2) {
                if (is_zero(value)) {
                    storage_[address][incarnation].erase(location);
                } else {
                    storage_[address][incarnation][location] = value;
                }
            }
        }
    }
}

size_t MemoryBuffer::number_of_accounts() const { return accounts_.size(); }

size_t MemoryBuffer::storage_size(const evmc::address& address, uint64_t incarnation) const {
    auto it1{storage_.find(address)};
    if (it1 == storage_.end()) {
        return 0;
    }
    auto it2{it1->second.find(incarnation)};
    if (it2 == it1->second.end()) {
        return 0;
    }

    return it2->second.size();
}

// https://eth.wiki/fundamentals/patricia-tree#storage-trie
evmc::bytes32 MemoryBuffer::account_storage_root(const evmc::address& address, uint64_t incarnation) const {
    auto it1{storage_.find(address)};
    if (it1 == storage_.end()) {
        return kEmptyRoot;
    }
    auto it2{it1->second.find(incarnation)};
    if (it2 == it1->second.end()) {
        return kEmptyRoot;
    }

    const auto& storage{it2->second};

    if (storage.empty()) {
        return kEmptyRoot;
    }

    std::map<evmc::bytes32, Bytes> storage_rlp;
    Bytes rlp;
    for (const auto& [location, value] : storage) {
        ethash::hash256 hash{keccak256(full_view(location))};
        rlp.clear();
        rlp::encode(rlp, zeroless_view(value));
        storage_rlp[to_bytes32(full_view(hash.bytes))] = rlp;
    }

    auto it{storage_rlp.cbegin()};
    trie::HashBuilder hb{full_view(it->first), it->second};
    for (++it; it != storage_rlp.cend(); ++it) {
        hb.add(full_view(it->first), it->second);
    }

    return hb.root_hash();
}

evmc::bytes32 MemoryBuffer::state_root_hash() const {
    if (accounts_.empty()) {
        return kEmptyRoot;
    }

    std::map<evmc::bytes32, Bytes> account_rlp;
    Bytes rlp;
    for (const auto& [address, account] : accounts_) {
        ethash::hash256 hash{keccak256(full_view(address))};
        Account copy{account};
        copy.storage_root = account_storage_root(address, account.incarnation);
        rlp.clear();
        rlp::encode(rlp, copy);
        account_rlp[to_bytes32(full_view(hash.bytes))] = rlp;
    }

    auto it{account_rlp.cbegin()};
    trie::HashBuilder hb{full_view(it->first), it->second};
    for (++it; it != account_rlp.cend(); ++it) {
        hb.add(full_view(it->first), it->second);
    }

    return hb.root_hash();
}

}  // namespace silkworm
