// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "in_memory_state.hpp"

#include <map>

#include <ethash/keccak.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/rlp/encode.hpp>
#include <silkworm/core/trie/hash_builder.hpp>
#include <silkworm/core/trie/nibbles.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

std::optional<Account> InMemoryState::read_account(const evmc::address& address) const noexcept {
    auto it{accounts_.find(address)};
    if (it == accounts_.end()) {
        return std::nullopt;
    }
    return it->second;
}

ByteView InMemoryState::read_code(const evmc::address& /*address*/, const evmc::bytes32& code_hash) const noexcept {
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

std::optional<BlockHeader> InMemoryState::read_header(BlockNum block_num,
                                                      const evmc::bytes32& block_hash) const noexcept {
    const auto it1 = headers_.find(block_num);
    if (it1 != headers_.end()) {
        const auto it2{it1->second.find(block_hash)};
        if (it2 != it1->second.end()) {
            return it2->second;
        }
    }
    return std::nullopt;
}

bool InMemoryState::read_body(BlockNum block_num, const evmc::bytes32& block_hash, BlockBody& out) const noexcept {
    const auto it1 = bodies_.find(block_num);
    if (it1 != bodies_.end()) {
        const auto it2{it1->second.find(block_hash)};
        if (it2 != it1->second.end()) {
            out = it2->second;
            return true;
        }
    }
    return false;
}

std::optional<intx::uint256> InMemoryState::total_difficulty(BlockNum block_num,
                                                             const evmc::bytes32& block_hash) const noexcept {
    const auto it1 = difficulty_.find(block_num);
    if (it1 != difficulty_.end()) {
        const auto it2{it1->second.find(block_hash)};
        if (it2 != it1->second.end()) {
            return it2->second;
        }
    }
    return std::nullopt;
}

BlockNum InMemoryState::current_canonical_block() const {
    if (canonical_hashes_.empty()) {
        return 0;
    }
    return canonical_hashes_.rbegin()->first;
}

std::optional<evmc::bytes32> InMemoryState::canonical_hash(BlockNum block_num) const {
    const auto& ret = canonical_hashes_.find(block_num);
    if (ret != canonical_hashes_.end()) {
        return ret->second;
    }
    return std::nullopt;
}

void InMemoryState::insert_block(const Block& block, const evmc::bytes32& hash) {
    BlockNum block_num = block.header.number;

    headers_[block_num][hash] = block.header;
    bodies_[block_num][hash] = block.copy_body();
    if (block_num == 0) {
        difficulty_[block_num][hash] = 0;
    } else {
        difficulty_[block_num][hash] = difficulty_[block_num - 1][block.header.parent_hash];
    }
    difficulty_[block_num][hash] += block.header.difficulty;
}

void InMemoryState::canonize_block(BlockNum block_num, const evmc::bytes32& block_hash) {
    canonical_hashes_[block_num] = block_hash;
}

void InMemoryState::decanonize_block(BlockNum block_num) { (void)canonical_hashes_.erase(block_num); }

void InMemoryState::insert_receipts(BlockNum, const std::vector<Receipt>&) {}

void InMemoryState::insert_call_traces(BlockNum /*block_num*/, const CallTraces& /*traces*/) {}

void InMemoryState::begin_block(BlockNum block_num, size_t /*updated_accounts_count*/) {
    block_num_ = block_num;
    account_changes_.erase(block_num);
    storage_changes_.erase(block_num);
}

void InMemoryState::update_account(const evmc::address& address, std::optional<Account> initial,
                                   std::optional<Account> current) {
    // Skip update if both initial and final state are non-existent (i.e. contract creation+destruction within the same block)
    if (!initial && !current) {
        return;
    }
    account_changes_[block_num_][address] = initial;

    // Store current account or delete it
    if (current) {
        accounts_[address] = current.value();
    } else {
        accounts_.erase(address);
    }

    // Remember the previous incarnation when an initially existing contract gets deleted, i.e. current is empty or EOA
    const bool initial_smart{initial && initial->incarnation};
    const bool current_deleted_or_eoa{!current || current->incarnation == 0};
    if (initial_smart && current_deleted_or_eoa) {
        prev_incarnations_[address] = initial.value().incarnation;
    }
}

void InMemoryState::update_account_code(const evmc::address&, uint64_t, const evmc::bytes32& code_hash, ByteView code) {
    // Don't overwrite already existing code so that views of it
    // that were previously returned by read_code() are still valid.
    code_.try_emplace(code_hash, code);
}

void InMemoryState::update_storage(const evmc::address& address, uint64_t incarnation, const evmc::bytes32& location,
                                   const evmc::bytes32& initial, const evmc::bytes32& current) {
    storage_changes_[block_num_][address][incarnation][location] = initial;

    if (is_zero(current)) {
        storage_[address][incarnation].erase(location);
    } else {
        storage_[address][incarnation][location] = current;
    }
}

void InMemoryState::unwind_state_changes(BlockNum block_num) {
    for (const auto& [address, account] : account_changes_[block_num]) {
        if (account) {
            accounts_[address] = *account;
        } else {
            accounts_.erase(address);
        }
    }

    for (const auto& [address, storage1] : storage_changes_[block_num]) {
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
        ethash::hash256 hash{keccak256(location.bytes)};
        buffer.clear();
        rlp::encode(buffer, zeroless_view(value.bytes));
        storage_rlp[to_bytes32(hash.bytes)] = buffer;
    }

    trie::HashBuilder hb;
    for (const auto& [hash, rlp] : storage_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash.bytes), rlp);
    }

    return hb.root_hash();
}

evmc::bytes32 InMemoryState::state_root_hash() const {
    if (accounts_.empty()) {
        return kEmptyRoot;
    }

    std::map<evmc::bytes32, Bytes> account_rlp;
    for (const auto& [address, account] : accounts_) {
        ethash::hash256 hash{keccak256(address.bytes)};
        evmc::bytes32 storage_root{account_storage_root(address, account.incarnation)};
        account_rlp[to_bytes32(hash.bytes)] = account.rlp(storage_root);
    }

    trie::HashBuilder hb;
    for (const auto& [hash, rlp] : account_rlp) {
        hb.add_leaf(trie::unpack_nibbles(hash.bytes), rlp);
    }

    return hb.root_hash();
}
}  // namespace silkworm
