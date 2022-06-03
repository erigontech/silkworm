/*
   Copyright 2020-2022 The Silkworm Authors

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

#include "in_memory_state.hpp"

#include <map>

#include <ethash/keccak.hpp>

#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>
#include <silkworm/trie/hash_builder.hpp>

namespace silkworm {

std::optional<Account> InMemoryState::read_account(const evmc::address& address) const noexcept {
    auto it{accounts_.find(address)};
    if (it == accounts_.end()) {
        return std::nullopt;
    }
    return it->second;
}

ByteView InMemoryState::read_code(const evmc::bytes32& code_hash) const noexcept {
    auto it{code_.find(code_hash)};
    if (it == code_.end()) {
        return {};
    }
    return it->second;
}

evmc::bytes32 InMemoryState::read_storage(const evmc::address& address, uint64_t incarnation,
                                          const evmc::bytes32& location) const noexcept {
    const auto it1{storage_.find(address)};
    if (it1 != storage_.end()) {
        const auto it2{it1->second.find(incarnation)};
        if (it2 != it1->second.end()) {
            const auto it3{it2->second.find(location)};
            if (it3 != it2->second.end()) {
                return it3->second;
            }
        }
    }
    return {};
}

uint64_t InMemoryState::previous_incarnation(const evmc::address& address) const noexcept {
    auto it{prev_incarnations_.find(address)};
    if (it == prev_incarnations_.end()) {
        return 0;
    }
    return it->second;
}

std::optional<BlockHeader> InMemoryState::read_header(uint64_t block_number,
                                                      const evmc::bytes32& block_hash) const noexcept {
    const auto it1{headers_.find(block_number)};
    if (it1 != headers_.end()) {
        const auto it2{it1->second.find(block_hash)};
        if (it2 != it1->second.end()) {
            return it2->second;
        }
    }
    return std::nullopt;
}

bool InMemoryState::read_body(uint64_t block_number, const evmc::bytes32& block_hash, BlockBody& out) const noexcept {
    const auto it1{bodies_.find(block_number)};
    if (it1 != bodies_.end()) {
        const auto it2{it1->second.find(block_hash)};
        if (it2 != it1->second.end()) {
            out = it2->second;
            return true;
        }
    }
    return false;
}

std::optional<intx::uint256> InMemoryState::total_difficulty(uint64_t block_number,
                                                             const evmc::bytes32& block_hash) const noexcept {
    const auto it1{difficulty_.find(block_number)};
    if (it1 != difficulty_.end()) {
        const auto it2{it1->second.find(block_hash)};
        if (it2 != it1->second.end()) {
            return it2->second;
        }
    }
    return std::nullopt;
}

uint64_t InMemoryState::current_canonical_block() const {
    if (canonical_hashes_.empty()) {
        return 0;
    }
    return canonical_hashes_.rbegin()->first;
}

std::optional<evmc::bytes32> InMemoryState::canonical_hash(uint64_t block_number) const {
    const auto& ret{canonical_hashes_.find(block_number)};
    if (ret != canonical_hashes_.end()) {
        return ret->second;
    }
    return std::nullopt;
}

void InMemoryState::insert_block(const Block& block, const evmc::bytes32& hash) {
    uint64_t block_number{block.header.number};

    headers_[block_number][hash] = block.header;
    bodies_[block_number][hash] = block;
    if (block_number == 0) {
        difficulty_[block_number][hash] = 0;
    } else {
        difficulty_[block_number][hash] = difficulty_[block_number - 1][block.header.parent_hash];
    }
    difficulty_[block_number][hash] += block.header.difficulty;
}

void InMemoryState::canonize_block(uint64_t block_number, const evmc::bytes32& block_hash) {
    canonical_hashes_[block_number] = block_hash;
}

void InMemoryState::decanonize_block(uint64_t block_number) { (void)canonical_hashes_.erase(block_number); }

void InMemoryState::insert_receipts(uint64_t, const std::vector<Receipt>&) {}

void InMemoryState::begin_block(uint64_t block_number) {
    block_number_ = block_number;
    account_changes_.erase(block_number);
    storage_changes_.erase(block_number);
}

void InMemoryState::update_account(const evmc::address& address, std::optional<Account> initial,
                                   std::optional<Account> current) {
    account_changes_[block_number_][address] = initial;

    if (current.has_value()) {
        accounts_[address] = current.value();
    } else {
        accounts_.erase(address);
        if (initial.has_value()) {
            prev_incarnations_[address] = initial.value().incarnation;
        }
    }
}

void InMemoryState::update_account_code(const evmc::address&, uint64_t, const evmc::bytes32& code_hash, ByteView code) {
    // Don't overwrite already existing code so that views of it
    // that were previously returned by read_code() are still valid.
    code_.try_emplace(code_hash, code);
}

void InMemoryState::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                                   const evmc::bytes32& initial, const evmc::bytes32& current) {
    storage_changes_[block_number_][address][incarnation][location] = initial;

    if (is_zero(current)) {
        storage_[address][incarnation].erase(location);
    } else {
        storage_[address][incarnation][location] = current;
    }
}

void InMemoryState::unwind_state_changes(uint64_t block_number) {
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

size_t InMemoryState::number_of_accounts() const { return accounts_.size(); }

size_t InMemoryState::storage_size(const evmc::address& address, uint64_t incarnation) const {
    const auto it1{storage_.find(address)};
    if (it1 != storage_.end()) {
        const auto it2{it1->second.find(incarnation)};
        if (it2 != it1->second.end()) {
            return it2->second.size();
        }
    }
    return 0;
}

// https://eth.wiki/fundamentals/patricia-tree#storage-trie
evmc::bytes32 InMemoryState::account_storage_root(const evmc::address& address, uint64_t incarnation) const {
    auto it1{storage_.find(address)};
    if (it1 == storage_.end()) {
        return kEmptyRoot;
    }
    auto it2{it1->second.find(incarnation)};
    if (it2 == it1->second.end() || it2->second.empty()) {
        return kEmptyRoot;
    }

    const auto& storage{it2->second};

    std::map<evmc::bytes32, Bytes> storage_rlp;
    Bytes buffer;
    for (const auto& [location, value] : storage) {
        ethash::hash256 hash{keccak256(location)};
        buffer.clear();
        rlp::encode(buffer, zeroless_view(value));
        storage_rlp[to_bytes32(hash.bytes)] = buffer;
    }

    trie::HashBuilder hb;
    for (const auto& [hash, rlp] : storage_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash), rlp);
    }

    return hb.root_hash();
}

evmc::bytes32 InMemoryState::state_root_hash() const {
    if (accounts_.empty()) {
        return kEmptyRoot;
    }

    std::map<evmc::bytes32, Bytes> account_rlp;
    for (const auto& [address, account] : accounts_) {
        ethash::hash256 hash{keccak256(address)};
        evmc::bytes32 storage_root{account_storage_root(address, account.incarnation)};
        account_rlp[to_bytes32(hash.bytes)] = account.rlp(storage_root);
    }

    trie::HashBuilder hb;
    for (const auto& [hash, rlp] : account_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash), rlp);
    }

    return hb.root_hash();
}

}  // namespace silkworm
