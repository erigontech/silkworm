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

#include "memory_buffer.hpp"

#include <ethash/keccak.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/rlp/encode.hpp>

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

void MemoryBuffer::begin_block(uint64_t) {}

void MemoryBuffer::update_account(const evmc::address& address, std::optional<Account> initial,
                                  std::optional<Account> current) {
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
                                  const evmc::bytes32&, const evmc::bytes32& current) {
    storage_[address][incarnation][location] = current;
}

}  // namespace silkworm
