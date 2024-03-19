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
        .base_data_id = base_data_id_,
        .less_false_positives = less_false_positives_,
    };
    RecSplit8 rec_split1{rec_split_settings, rec_split::seq_build_strategy(etl_buffer_size_)};

    rec_split1.build_without_collisions([&](RecSplit8& rec_split) {
        uint64_t i{0};
        for (auto it = decoder.begin(); it != decoder.end(); ++it, ++i) {
            auto& word = *it;
            auto offset = it.current_word_offset();
            rec_split.add_key(make_key(word, i), offset);
        }
    });

    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " end";
}

Bytes HeaderIndex::make_key(ByteView word, uint64_t i) {
    ensure(!word.empty(), [&]() { return "HeaderIndex: word empty i=" + std::to_string(i); });
    const uint8_t first_hash_byte{word[0]};
    const ByteView rlp_encoded_header{word.data() + 1, word.size() - 1};
    const ethash::hash256 hash = keccak256(rlp_encoded_header);
    ensure(hash.bytes[0] == first_hash_byte,
           [&]() { return "HeaderIndex: invalid prefix=" + to_hex(first_hash_byte) + " hash=" + to_hex(hash.bytes); });
    return Bytes{ByteView{hash.bytes}};
}

Bytes BodyIndex::make_key(ByteView /*word*/, uint64_t i) {
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

SnapshotPath TransactionIndex::bodies_segment_path() const {
    return SnapshotPath::from(
        segment_path_.path().parent_path(),
        segment_path_.version(),
        segment_path_.block_from(),
        segment_path_.block_to(),
        SnapshotType::bodies);
}

std::pair<uint64_t, uint64_t> TransactionIndex::compute_txs_amount() {
    BodySnapshot bodies_snapshot{bodies_segment_path()};
    bodies_snapshot.reopen_segment();
    return bodies_snapshot.compute_txs_amount();
}

uint64_t TransactionIndex::read_tx_count() {
    seg::Decompressor txs_decoder{segment_path_.path(), segment_region_};
    txs_decoder.open();
    return txs_decoder.words_count();
}

void TransactionIndex::build() {
    const SnapshotPath bodies_segment_path = this->bodies_segment_path();
    SILK_TRACE << "TransactionIndex::build bodies_segment path: " << bodies_segment_path.path().string();

    const auto txs_amount = compute_txs_amount();
    const uint64_t first_tx_id = txs_amount.first;
    const uint64_t expected_tx_count = txs_amount.second;
    SILK_TRACE << "TransactionIndex::build first_tx_id: " << first_tx_id << " expected_tx_count: " << expected_tx_count;

    const auto tx_count = read_tx_count();
    if (expected_tx_count != tx_count) {
        std::stringstream error;
        error << "TransactionIndex::build cannot build index for: " << segment_path_.path()
              << " tx count mismatch: expected=" << std::to_string(expected_tx_count)
              << " got=" << std::to_string(tx_count);
        throw std::runtime_error{error.str()};
    }

    base_data_id_ = first_tx_id;
    less_false_positives_ = true;
    etl_buffer_size_ = db::etl::kOptimalBufferSize / 2;
    Index::build();

    SILK_TRACE << "TransactionIndex::build path: " << segment_path_.path().string() << " start";

    seg::Decompressor txs_decoder{segment_path_.path(), segment_region_};
    txs_decoder.open();

    const BlockNum first_block_num{segment_path_.block_from()};

    const SnapshotPath tx2block_idx_file = segment_path_.index_file_for_type(SnapshotType::transactions_to_block);
    SILK_TRACE << "TransactionIndex::build tx2block_idx_file path: " << tx2block_idx_file.path().string();
    RecSplitSettings tx_hash_to_block_rs_settings{
        .keys_count = txs_decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = tx2block_idx_file.path(),
        .base_data_id = first_block_num,
        .double_enum_index = false};
    RecSplit8 tx_hash_to_block_rs1{tx_hash_to_block_rs_settings, rec_split::seq_build_strategy(etl_buffer_size_)};

    seg::Decompressor bodies_decoder{bodies_segment_path.path()};
    bodies_decoder.open();

    tx_hash_to_block_rs1.build_without_collisions([&](RecSplit8& tx_hash_to_block_rs) {
        {
            {
                auto body_it = bodies_decoder.begin();
                if (body_it == bodies_decoder.end()) {
                    throw std::runtime_error{"TransactionIndex::build no bodies to build transactions index for: " + segment_path_.path().string()};
                }

                BlockNum block_number = first_block_num;
                BlockBodyForStorage body;
                ByteView body_rlp = *body_it;
                SILK_TRACE << "double_read_ahead block_number: " << block_number << " body_rlp: " << to_hex(body_rlp);
                auto decode_result = decode_stored_block_body(body_rlp, body);
                if (!decode_result) {
                    std::stringstream error;
                    error << "TransactionIndex::build cannot build index for: " << segment_path_.path()
                          << " cannot decode block " << block_number
                          << " body: " << to_hex(body_rlp)
                          << " error: " << magic_enum::enum_name(decode_result.error());
                    throw std::runtime_error{error.str()};
                }

                uint64_t i{0};
                for (auto& tx_buffer : txs_decoder) {
                    while (body.base_txn_id + body.txn_count <= first_tx_id + i) {
                        ++body_it;
                        if (body_it == bodies_decoder.end()) {
                            throw std::runtime_error{"TransactionIndex::build not enough bodies to build transactions index for: " + segment_path_.path().string()};
                        }
                        body_rlp = *body_it;
                        decode_result = decode_stored_block_body(body_rlp, body);
                        if (!decode_result) {
                            std::stringstream error;
                            error << "TransactionIndex::build cannot build index for: " << segment_path_.path()
                                  << " cannot decode block " << block_number
                                  << " body: " << to_hex(body_rlp)
                                  << " i: " << i
                                  << " error: " << magic_enum::enum_name(decode_result.error());
                            throw std::runtime_error{error.str()};
                        }
                        ++block_number;
                    }

                    tx_hash_to_block_rs.add_key(make_key(tx_buffer, i), block_number);
                    i++;
                }

                if (i != expected_tx_count) {
                    std::stringstream error;
                    error << "TransactionIndex::build cannot build index for: " << segment_path_.path()
                          << " tx count mismatch: expected=" + std::to_string(expected_tx_count)
                          << " got=" << std::to_string(i);
                    throw std::runtime_error{error.str()};
                }
            }
        }
    });

    SILK_TRACE << "TransactionIndex::build path: " << segment_path_.path().string() << " end";
}

Bytes TransactionIndex::make_key(ByteView word, uint64_t i) {
    Bytes tx_hash;
    try {
        tx_hash = tx_buffer_hash(word, base_data_id_ + i);
    } catch (const std::runtime_error& ex) {
        std::stringstream error;
        error << "TransactionIndex::build cannot build index for: " << segment_path_.path()
              << ex.what();
        throw std::runtime_error{error.str()};
    }
    return tx_hash;
}

}  // namespace silkworm::snapshots
