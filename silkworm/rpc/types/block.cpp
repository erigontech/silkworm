/*
   Copyright 2023 The Silkworm Authors

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

#include <absl/strings/match.h>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>
#include <silkworm/rpc/core/block_reader.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const Block& b) {
    out << b.to_string();
    return out;
}

std::string Block::to_string() const {
    const auto& b = *this;
    std::stringstream out;

    auto& block = b.block_with_hash->block;
    out << "parent_hash: " << to_hex(block.header.parent_hash);
    out << " ommers_hash: " << to_hex(block.header.ommers_hash);
    out << " beneficiary: ";
    for (const auto& byte : block.header.beneficiary.bytes) {
        out << std::hex << std::setw(2) << std::setfill('0') << int{byte};
    }
    out << std::dec;
    out << " state_root: " << to_hex(block.header.state_root);
    out << " transactions_root: " << to_hex(block.header.transactions_root);
    out << " receipts_root: " << to_hex(block.header.receipts_root);
    out << " logs_bloom: " << silkworm::to_hex(full_view(block.header.logs_bloom));
    out << " difficulty: " << silkworm::to_hex(silkworm::endian::to_big_compact(block.header.difficulty));
    out << " number: " << block.header.number;
    out << " gas_limit: " << block.header.gas_limit;
    out << " gas_used: " << block.header.gas_used;
    out << " timestamp: " << block.header.timestamp;
    out << " extra_data: " << silkworm::to_hex(block.header.extra_data);
    out << " prev_randao: " << to_hex(block.header.prev_randao);
    out << " nonce: " << silkworm::to_hex({block.header.nonce.data(), block.header.nonce.size()});
    out << " #transactions: " << block.transactions.size();
    out << " #ommers: " << block.ommers.size();
    out << " hash: " << to_hex(b.block_with_hash->hash);
    out << " full_tx: " << b.full_tx;
    return out.str();
}

uint64_t Block::get_block_size() const {
    silkworm::rlp::Header rlp_head{true, 0};
    auto& block = block_with_hash->block;
    rlp_head.payload_length = silkworm::rlp::length(block.header);
    rlp_head.payload_length += silkworm::rlp::length(block.transactions);
    rlp_head.payload_length += silkworm::rlp::length(block.ommers);
    if (block.withdrawals) {
        rlp_head.payload_length += silkworm::rlp::length(*(block.withdrawals));
    }
    rlp_head.payload_length += silkworm::rlp::length_of_length(rlp_head.payload_length);
    return rlp_head.payload_length;
}

std::ostream& operator<<(std::ostream& out, const BlockNumOrHash& block_num_or_hash) {
    out << block_num_or_hash.to_string();
    return out;
}

std::string BlockNumOrHash::to_string() const {
    const auto& block_num_or_hash = *this;
    std::stringstream out;

    if (block_num_or_hash.is_number()) {
        out << "0x" << std::hex << block_num_or_hash.number() << std::dec;
    } else if (block_num_or_hash.is_hash()) {
        out << to_hex(block_num_or_hash.hash(), true);
    } else {
        SILKWORM_ASSERT(block_num_or_hash.is_tag());
        out << block_num_or_hash.tag();
    }
    return out.str();
}

void BlockNumOrHash::parse(const std::string& block_num_or_hash) {
    value_ = uint64_t{0};
    if (block_num_or_hash == kEarliestBlockId) {
        value_ = kEarliestBlockNum;
    } else if (block_num_or_hash == kLatestBlockId ||
               block_num_or_hash == kPendingBlockId ||
               block_num_or_hash == kFinalizedBlockId ||
               block_num_or_hash == kSafeBlockId) {
        value_ = block_num_or_hash;
    } else if (absl::StartsWithIgnoreCase(block_num_or_hash, "0x")) {
        if (block_num_or_hash.size() == 66) {
            const auto b32_bytes = silkworm::from_hex(block_num_or_hash);
            const auto b32 = silkworm::to_bytes32(b32_bytes.value_or(silkworm::Bytes{}));
            value_ = b32;
        } else {
            value_ = std::stoul(block_num_or_hash, nullptr, 16);
        }
    } else {
        value_ = std::stoul(block_num_or_hash, nullptr, 10);
    }
}

}  // namespace silkworm::rpc
