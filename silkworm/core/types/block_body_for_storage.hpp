/*
   Copyright 2024 The Silkworm Authors

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

#pragma once

#include <cstdint>
#include <optional>
#include <vector>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/decoding_result.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/withdrawal.hpp>

// keep below
#include <silkworm/core/rlp/decode_vector.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>

namespace silkworm {

// See Erigon BodyForStorage
struct BlockBodyForStorage {
    uint64_t base_txn_id{0};
    uint64_t txn_count{0};
    std::vector<BlockHeader> ommers;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};  // EIP-4895

    [[nodiscard]] Bytes encode() const;

    friend bool operator==(const BlockBodyForStorage&, const BlockBodyForStorage&) = default;
};

DecodingResult decode_stored_block_body(ByteView& from, BlockBodyForStorage& to);

tl::expected<BlockBodyForStorage, DecodingError> decode_stored_block_body(ByteView& from);

inline Bytes BlockBodyForStorage::encode() const {
    rlp::Header header{.list = true, .payload_length = 0};
    header.payload_length += rlp::length(base_txn_id);
    header.payload_length += rlp::length(txn_count);
    header.payload_length += rlp::length(ommers);
    if (withdrawals) {
        header.payload_length += rlp::length(*withdrawals);
    }

    Bytes to;
    rlp::encode_header(to, header);
    rlp::encode(to, base_txn_id);
    rlp::encode(to, txn_count);
    rlp::encode(to, ommers);
    if (withdrawals) {
        rlp::encode(to, *withdrawals);
    }

    return to;
}

inline DecodingResult decode_stored_block_body(ByteView& from, BlockBodyForStorage& to) {
    const auto header{rlp::decode_header(from)};
    if (!header) {
        return tl::unexpected{header.error()};
    }
    if (!header->list) {
        return tl::unexpected{DecodingError::kUnexpectedString};
    }
    const uint64_t leftover{from.length() - header->payload_length};
    if (leftover) {
        return tl::unexpected{DecodingError::kInputTooLong};
    }

    if (DecodingResult res{rlp::decode_items(from, to.base_txn_id, to.txn_count, to.ommers)}; !res) {
        return res;
    }

    to.withdrawals = std::nullopt;
    if (from.length() > leftover) {
        std::vector<Withdrawal> withdrawals;
        if (DecodingResult res{rlp::decode(from, withdrawals, rlp::Leftover::kAllow)}; !res) {
            return res;
        }
        to.withdrawals = withdrawals;
    }

    if (from.length() != leftover) {
        return tl::unexpected{DecodingError::kUnexpectedListElements};
    }
    return {};
}

inline tl::expected<BlockBodyForStorage, DecodingError> decode_stored_block_body(ByteView& from) {
    BlockBodyForStorage to;
    DecodingResult result = decode_stored_block_body(from, to);
    if (!result)
        return tl::unexpected{result.error()};
    return to;
}

}  // namespace silkworm
