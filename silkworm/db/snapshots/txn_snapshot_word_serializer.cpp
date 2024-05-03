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

#include "txn_snapshot_word_serializer.hpp"

#include <algorithm>
#include <sstream>
#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

TransactionSnapshotWord slice_tx_data(ByteView buffer) {
    // Skip first byte of tx hash plus sender address length for transaction decoding
    constexpr int kTxRlpDataOffset{1 + kAddressLength};

    if (buffer.size() < kTxRlpDataOffset) {
        std::stringstream error;
        error << "slice_tx_data too short record: " << std::to_string(buffer.size());
        throw std::runtime_error{error.str()};
    }

    uint8_t first_hash_byte = buffer[0];
    ByteView senders_data = buffer.substr(1, kAddressLength);
    ByteView tx_rlp = buffer.substr(kTxRlpDataOffset);

    return TransactionSnapshotWord{
        first_hash_byte,
        senders_data,
        tx_rlp,
    };
}

ByteView slice_tx_payload(ByteView tx_rlp) {
    ByteView tx_envelope = tx_rlp;
    rlp::Header tx_header;
    TransactionType tx_type{};
    const auto decode_result = rlp::decode_transaction_header_and_type(tx_envelope, tx_header, tx_type);
    if (!decode_result) {
        std::stringstream error;
        error << "slice_tx_payload cannot decode tx envelope: " << to_hex(tx_rlp)
              << " error: " << magic_enum::enum_name(decode_result.error());
        throw std::runtime_error{error.str()};
    }

    if (tx_type == TransactionType::kLegacy)
        return tx_rlp;

    if (tx_rlp.size() < tx_header.payload_length) {
        std::stringstream error;
        error << " slice_tx_payload cannot decode tx payload: " << to_hex(tx_rlp)
              << " too short: " << tx_rlp.size()
              << " payload_length: " << tx_header.payload_length;
        throw std::runtime_error{error.str()};
    }

    const std::size_t tx_payload_offset = tx_rlp.size() - tx_header.payload_length;
    return tx_rlp.substr(tx_payload_offset);
}

void decode_word_into_tx(ByteView word, Transaction& tx) {
    auto [_, senders_data, tx_rlp] = slice_tx_data(word);
    const auto result = rlp::decode(tx_rlp, tx);
    success_or_throw(result, "decode_word_into_tx: rlp::decode error");
    // Must happen after rlp::decode because it resets sender
    tx.set_sender(bytes_to_address(senders_data));
}

Hash tx_buffer_hash(ByteView tx_buffer, uint64_t tx_id) {
    Hash tx_hash;

    const bool is_system_tx{tx_buffer.empty()};
    if (is_system_tx) {
        // system-txs: hash:pad32(txnID)
        endian::store_big_u64(tx_hash.bytes, tx_id);
        return tx_hash;
    }

    auto [_1, _2, tx_envelope] = slice_tx_data(tx_buffer);
    const ByteView tx_payload = slice_tx_payload(tx_envelope);

    const auto h256{keccak256(tx_payload)};
    std::copy(std::begin(h256.bytes), std::begin(h256.bytes) + kHashLength, std::begin(tx_hash.bytes));

    if (tx_id % 100'000 == 0) {
        SILK_DEBUG << "tx_buffer_hash:"
                   << " header.payload_length: " << tx_payload.size()
                   << " tx_id: " << tx_id;
    }
    SILK_TRACE << "tx_buffer_hash:"
               << " tx_id: " << tx_id
               << " payload: " << to_hex(tx_payload)
               << " h256: " << to_hex(h256.bytes, kHashLength);

    return tx_hash;
}

}  // namespace silkworm::snapshots
