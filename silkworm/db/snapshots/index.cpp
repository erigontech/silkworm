/*
   Copyright 2022 The Silkworm Authors

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

#include "index.hpp"

#include <sstream>
#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/db/snapshots/rec_split/rec_split.hpp>
#include <silkworm/db/snapshots/rec_split/rec_split_seq.hpp>
#include <silkworm/db/snapshots/seg/common/varint.hpp>
#include <silkworm/db/snapshots/snapshot.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

namespace silkworm::snapshots {

using RecSplitSettings = rec_split::RecSplitSettings;
using RecSplit8 = rec_split::RecSplit8;

void Index::build() {
    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " start";

    seg::Decompressor decoder{segment_path_.path(), segment_region_};
    decoder.open();

    const SnapshotPath index_file = segment_path_.index_file();
    RecSplitSettings rec_split_settings{
        .keys_count = decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = index_file.path(),
        .base_data_id = descriptor_.base_data_id,
        .double_enum_index = true,
        .less_false_positives = descriptor_.less_false_positives,
    };
    RecSplit8 rec_split1{rec_split_settings, rec_split::seq_build_strategy(descriptor_.etl_buffer_size)};

    rec_split1.build_without_collisions([&](RecSplit8& rec_split) {
        uint64_t i{0};
        for (auto it = decoder.begin(); it != decoder.end(); ++it, ++i) {
            auto& word = *it;
            auto offset = it.current_word_offset();
            rec_split.add_key(descriptor_.key_factory->make(word, i), offset);
        }
    });

    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " end";
}

Bytes HeaderIndex::KeyFactory::make(ByteView word, uint64_t i) {
    ensure(!word.empty(), [&]() { return "HeaderIndex: word empty i=" + std::to_string(i); });
    const uint8_t first_hash_byte{word[0]};
    const ByteView rlp_encoded_header{word.data() + 1, word.size() - 1};
    const ethash::hash256 hash = keccak256(rlp_encoded_header);
    ensure(hash.bytes[0] == first_hash_byte,
           [&]() { return "HeaderIndex: invalid prefix=" + to_hex(first_hash_byte) + " hash=" + to_hex(hash.bytes); });
    return Bytes{ByteView{hash.bytes}};
}

Bytes BodyIndex::KeyFactory::make(ByteView /*word*/, uint64_t i) {
    Bytes uint64_buffer;
    seg::varint::encode(uint64_buffer, i);
    return uint64_buffer;
}

static Hash tx_buffer_hash(ByteView tx_buffer, uint64_t tx_id) {
    Hash tx_hash;

    const bool is_system_tx{tx_buffer.empty()};
    if (is_system_tx) {
        // system-txs: hash:pad32(txnID)
        endian::store_big_u64(tx_hash.bytes, tx_id);
        return tx_hash;
    }

    // Skip tx hash first byte plus address length for transaction decoding
    constexpr int kTxFirstByteAndAddressLength{1 + kAddressLength};
    if (tx_buffer.size() <= kTxFirstByteAndAddressLength) {
        std::stringstream error;
        error << " tx_buffer_hash cannot decode tx envelope: record " << to_hex(tx_buffer)
              << " too short: " << tx_buffer.size()
              << " tx_id: " << tx_id;
        throw std::runtime_error{error.str()};
    }
    const ByteView tx_envelope{tx_buffer.substr(kTxFirstByteAndAddressLength)};
    ByteView tx_envelope_view{tx_envelope};

    rlp::Header tx_header;
    TransactionType tx_type{};
    auto decode_result = rlp::decode_transaction_header_and_type(tx_envelope_view, tx_header, tx_type);
    if (!decode_result) {
        std::stringstream error;
        error << " tx_buffer_hash cannot decode tx envelope: " << to_hex(tx_envelope)
              << " tx_id: " << tx_id
              << " error: " << magic_enum::enum_name(decode_result.error());
        throw std::runtime_error{error.str()};
    }

    const std::size_t tx_payload_offset = tx_type == TransactionType::kLegacy ? 0 : (tx_envelope.length() - tx_header.payload_length);
    if (tx_buffer.size() <= kTxFirstByteAndAddressLength + tx_payload_offset) {
        std::stringstream error;
        error << " tx_buffer_hash cannot decode tx payload: record " << to_hex(tx_buffer)
              << " too short: " << tx_buffer.size()
              << " tx_id: " << tx_id;
        throw std::runtime_error{error.str()};
    }
    const ByteView tx_payload{tx_buffer.substr(kTxFirstByteAndAddressLength + tx_payload_offset)};
    const auto h256{keccak256(tx_payload)};
    std::copy(std::begin(h256.bytes), std::begin(h256.bytes) + kHashLength, std::begin(tx_hash.bytes));

    if (tx_id % 100'000 == 0) {
        SILK_DEBUG << "tx_buffer_hash:"
                   << " header.list: " << tx_header.list
                   << " header.payload_length: " << tx_header.payload_length
                   << " tx_id: " << tx_id;
    }
    SILK_TRACE << "tx_buffer_hash:"
               << " type: " << int(tx_type)
               << " tx_id: " << tx_id
               << " payload: " << to_hex(tx_payload)
               << " h256: " << to_hex(h256.bytes, kHashLength);

    return tx_hash;
}

SnapshotPath TransactionIndex1::bodies_segment_path(const SnapshotPath& segment_path) {
    return SnapshotPath::from(
        segment_path.path().parent_path(),
        segment_path.version(),
        segment_path.block_from(),
        segment_path.block_to(),
        SnapshotType::bodies);
}

std::pair<uint64_t, uint64_t> TransactionIndex1::compute_txs_amount(const SnapshotPath& bodies_segment_path) {
    BodySnapshot bodies_snapshot{bodies_segment_path};
    bodies_snapshot.reopen_segment();
    return bodies_snapshot.compute_txs_amount();
}

void TransactionToBlockIndex::build() {
    const SnapshotPath index_file = segment_path_.index_file_for_type(SnapshotType::transactions_to_block);
    SILK_TRACE << "TransactionIndex::build path: " << index_file.path().string() << " start";

    RecSplitSettings rec_split_settings{
        .keys_count = expected_tx_count_,
        .bucket_size = kBucketSize,
        .index_path = index_file.path(),
        .base_data_id = descriptor_.base_data_id,
        .double_enum_index = false,
        .less_false_positives = descriptor_.less_false_positives,
    };
    RecSplit8 rec_split1{rec_split_settings, rec_split::seq_build_strategy(descriptor_.etl_buffer_size)};

    rec_split1.build_without_collisions([&](RecSplit8& rec_split) {
        uint64_t i{0};
        for (auto& value : *query_) {
            rec_split.add_key(descriptor_.key_factory->make(value.tx_buffer, i), value.block_number);
            i++;
        }
    });

    SILK_TRACE << "TransactionIndex::build path: " << segment_path_.path().string() << " end";
}

Bytes TransactionKeyFactory::make(ByteView word, uint64_t i) {
    return Bytes{tx_buffer_hash(word, first_tx_id_ + i)};
}

}  // namespace silkworm::snapshots
