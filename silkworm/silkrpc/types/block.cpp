/*
    Copyright 2020 The Silkrpc Authors

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

#include "block.hpp"

#include <string>

#include <silkworm/silkrpc/common/util.hpp>
#include <silkworm/silkrpc/core/blocks.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkrpc {

std::ostream& operator<<(std::ostream& out, const Block& b) {
    out << "parent_hash: " << b.block.header.parent_hash;
    out << " ommers_hash: " << b.block.header.ommers_hash;
    out << " beneficiary: ";
    for (const auto& byte : b.block.header.beneficiary.bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int(byte);
    }
    out << std::dec;
    out << " state_root: " << b.block.header.state_root;
    out << " transactions_root: " << b.block.header.transactions_root;
    out << " receipts_root: " << b.block.header.receipts_root;
    out << " logs_bloom: " << silkworm::to_hex(full_view(b.block.header.logs_bloom));
    out << " difficulty: " << silkworm::to_hex(silkworm::endian::to_big_compact(b.block.header.difficulty));
    out << " number: " << b.block.header.number;
    out << " gas_limit: " << b.block.header.gas_limit;
    out << " gas_used: " << b.block.header.gas_used;
    out << " timestamp: " << b.block.header.timestamp;
    out << " extra_data: " << silkworm::to_hex(b.block.header.extra_data);
    out << " mix_hash: " << b.block.header.mix_hash;
    out << " nonce: " << silkworm::to_hex({b.block.header.nonce.data(), b.block.header.nonce.size()});
    out << " #transactions: " << b.block.transactions.size();
    out << " #ommers: " << b.block.ommers.size();
    out << " hash: " << b.hash;
    out << " total_difficulty: " << silkworm::to_hex(silkworm::endian::to_big_compact(b.total_difficulty));
    out << " full_tx: " << b.full_tx;
    return out;
}

uint64_t Block::get_block_size() const {
   silkworm::rlp::Header rlp_head{true, 0};
   rlp_head.payload_length = silkworm::rlp::length(block.header);
   rlp_head.payload_length += silkworm::rlp::length(block.transactions);
   rlp_head.payload_length += silkworm::rlp::length(block.ommers);
   rlp_head.payload_length += silkworm::rlp::length_of_length(rlp_head.payload_length);
   return rlp_head.payload_length;
}

std::ostream& operator<<(std::ostream& out, const BlockNumberOrHash& bnoh) {
    if (bnoh.is_number()) {
        out << "0x" << std::hex << bnoh.number() << std::dec;
    } else if (bnoh.is_hash()) {
        out << "0x" << bnoh.hash();
    } else {
        SILKWORM_ASSERT(bnoh.is_tag());
        out << bnoh.tag();
    }
    return out;
}

void BlockNumberOrHash::build(const std::string& bnoh) {
    value_ = uint64_t{0};
    if (bnoh == core::kEarliestBlockId) {
        value_ = core::kEarliestBlockNumber;
    } else if (bnoh == core::kLatestBlockId || bnoh == core::kPendingBlockId) {
        value_ = bnoh;
    } else if (bnoh.find("0x") == 0 || bnoh.find("0X") == 0) {
        if (bnoh.length() == 66) {
            const auto b32_bytes = silkworm::from_hex(bnoh);
            const auto b32 = silkworm::to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
            value_ = b32;
        } else {
            value_ = std::stoul(bnoh, nullptr, 16);
        }
    } else {
        value_ = std::stoul(bnoh, nullptr, 10);
    }
}

} // namespace silkrpc
