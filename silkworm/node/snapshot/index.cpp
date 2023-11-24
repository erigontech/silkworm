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

#include <stdexcept>

#include <magic_enum.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/hash.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/thread_pool.hpp>
#include <silkworm/node/test/snapshots.hpp>

namespace silkworm::snapshot {

void Index::build() {
    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " start";

    huffman::Decompressor decoder{segment_path_.path(), segment_region_};
    decoder.open();

    const SnapshotPath index_file = segment_path_.index_file();
    RecSplitSettings rec_split_settings{
        .keys_count = decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = index_file.path(),
        .base_data_id = index_file.block_from()};
    RecSplit8 rec_split{rec_split_settings, std::make_unique<RecSplit8::SequentialBuildingStrategy>(etl::kOptimalBufferSize)};

    SILK_TRACE << "Build index for: " << segment_path_.path().string() << " start";
    uint64_t iterations{0};
    bool collision_detected;
    do {
        iterations++;
        SILK_TRACE << "Process snapshot items to prepare index build for: " << segment_path_.path().string();
        const bool read_ok = decoder.read_ahead([&](huffman::Decompressor::Iterator it) {
            Bytes word{};
            word.reserve(kPageSize);
            uint64_t i{0}, offset{0};
            while (it.has_next()) {
                uint64_t next_position = it.next(word);
                if (bool ok = walk(rec_split, i, offset, word); !ok) {
                    return false;
                }
                ++i;
                offset = next_position;
                word.clear();
            }
            return true;
        });
        if (!read_ok) throw std::runtime_error{"cannot build index for: " + segment_path_.path().string()};

        SILK_TRACE << "Build RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected = rec_split.build();
        SILK_DEBUG << "Build RecSplit index collision_detected: " << collision_detected << " [" << iterations << "]";
        if (collision_detected) rec_split.reset_new_salt();
    } while (collision_detected);
    SILK_TRACE << "Build index for: " << segment_path_.path().string() << " end [iterations=" << iterations << "]";

    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " end";
}

bool HeaderIndex::walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView word) {
    ensure(!word.empty(), "HeaderIndex: word empty i=" + std::to_string(i));
    const uint8_t first_hash_byte{word[0]};
    const ByteView rlp_encoded_header{word.data() + 1, word.size() - 1};
    const ethash::hash256 hash = keccak256(rlp_encoded_header);
    ensure(hash.bytes[0] == first_hash_byte,
           "HeaderIndex: invalid prefix=" + to_hex(first_hash_byte) + " hash=" + to_hex(hash.bytes));
    rec_split.add_key(hash.bytes, kHashLength, offset);
    return true;
}

bool BodyIndex::walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView /*word*/) {
    Bytes uint64_buffer;
    const auto size = test::encode_varint<uint64_t>(i, uint64_buffer);
    rec_split.add_key(uint64_buffer.data(), size, offset);
    return true;
}

void TransactionIndex::build() {
    SILK_TRACE << "TransactionIndex::build path: " << segment_path_.path().string() << " start";

    const SnapshotPath bodies_segment_path = SnapshotPath::from(segment_path_.path().parent_path(),
                                                                segment_path_.version(),
                                                                segment_path_.block_from(),
                                                                segment_path_.block_to(),
                                                                SnapshotType::bodies);
    SILK_TRACE << "TransactionIndex::build bodies_segment path: " << bodies_segment_path.path().string();

    BodySnapshot bodies_snapshot{bodies_segment_path};
    bodies_snapshot.reopen_segment();
    const auto [first_tx_id, expected_tx_count] = bodies_snapshot.compute_txs_amount();
    SILK_TRACE << "TransactionIndex::build first_tx_id: " << first_tx_id << " expected_tx_count: " << expected_tx_count;

    huffman::Decompressor txs_decoder{segment_path_.path(), segment_region_};
    txs_decoder.open();

    const auto tx_count = txs_decoder.words_count();
    if (tx_count != expected_tx_count) {
        throw std::runtime_error{"tx count mismatch: expected=" + std::to_string(expected_tx_count) +
                                 " got=" + std::to_string(tx_count)};
    }

    const BlockNum first_block_num{segment_path_.block_from()};

    const SnapshotPath tx_idx_file = segment_path_.index_file();
    SILK_TRACE << "TransactionIndex::build tx_idx_file path: " << tx_idx_file.path().string();
    RecSplitSettings tx_hash_rs_settings{
        .keys_count = txs_decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = tx_idx_file.path(),
        .base_data_id = first_tx_id,
        .double_enum_index = true};
    RecSplit8 tx_hash_rs{tx_hash_rs_settings, std::make_unique<RecSplit8::SequentialBuildingStrategy>(etl::kOptimalBufferSize)};

    const SnapshotPath tx2block_idx_file = segment_path_.index_file_for_type(SnapshotType::transactions_to_block);
    SILK_TRACE << "TransactionIndex::build tx2block_idx_file path: " << tx2block_idx_file.path().string();
    RecSplitSettings tx_hash_to_block_rs_settings{
        .keys_count = txs_decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = tx2block_idx_file.path(),
        .base_data_id = first_block_num,
        .double_enum_index = false};
    RecSplit8 tx_hash_to_block_rs{tx_hash_to_block_rs_settings, std::make_unique<RecSplit8::SequentialBuildingStrategy>(etl::kOptimalBufferSize)};

    huffman::Decompressor bodies_decoder{bodies_segment_path.path()};
    bodies_decoder.open();

    using DoubleReadAheadFunc = std::function<bool(huffman::Decompressor::Iterator, huffman::Decompressor::Iterator)>;
    auto double_read_ahead = [&txs_decoder, &bodies_decoder](const DoubleReadAheadFunc& fn) -> bool {
        return txs_decoder.read_ahead([fn, &bodies_decoder](auto tx_it) -> bool {
            return bodies_decoder.read_ahead([fn, &tx_it](auto body_it) {
                return fn(tx_it, body_it);
            });
        });
    };

    SILK_TRACE << "Build index for: " << segment_path_.path().string() << " start";
    uint64_t iterations{0};
    Hash tx_hash;
    bool collision_detected;
    do {
        iterations++;
        SILK_TRACE << "Process snapshot items to prepare index build for: " << segment_path_.path().string();
        const bool read_ok = double_read_ahead(
            [&, first_tx_id = first_tx_id, expected_tx_count = expected_tx_count](auto tx_it, auto body_it) -> bool {
                BlockNum block_number = first_block_num;

                db::detail::BlockBodyForStorage body;

                Bytes tx_buffer{}, body_buffer{};
                tx_buffer.reserve(kPageSize);
                body_buffer.reserve(kPageSize);

                body_it.next(body_buffer);
                ByteView body_rlp{body_buffer.data(), body_buffer.length()};
                SILK_TRACE << "double_read_ahead block_number: " << block_number << " body_rlp: " << to_hex(body_rlp);
                auto decode_result = db::detail::decode_stored_block_body(body_rlp, body);
                if (!decode_result) {
                    SILK_ERROR << "cannot decode block " << block_number << " body: " << to_hex(body_rlp) << " error: " << magic_enum::enum_name(decode_result.error());
                    return false;
                }
                body_buffer.clear();

                uint64_t i{0}, offset{0};
                while (tx_it.has_next()) {
                    uint64_t next_position = tx_it.next(tx_buffer);
                    while (body.base_txn_id + body.txn_count <= first_tx_id + i) {
                        if (!body_it.has_next()) return false;
                        body_it.next(body_buffer);
                        body_rlp = ByteView{body_buffer.data(), body_buffer.length()};
                        decode_result = db::detail::decode_stored_block_body(body_rlp, body);
                        if (!decode_result) {
                            SILK_ERROR << "cannot decode block " << block_number << " body: " << to_hex(body_rlp) << " i: " << i << " error: " << magic_enum::enum_name(decode_result.error());
                            return false;
                        }
                        body_buffer.clear();
                        ++block_number;
                    }
                    const bool is_system_tx{tx_buffer.empty()};
                    if (is_system_tx) {
                        // system-txs: hash:pad32(txnID)
                        endian::store_big_u64(tx_hash.bytes, first_tx_id + i);

                        tx_hash_rs.add_key(tx_hash.bytes, kHashLength, offset);
                        tx_hash_to_block_rs.add_key(tx_hash.bytes, kHashLength, block_number);
                    } else {
                        // Skip tx hash first byte plus address length for transaction decoding
                        constexpr int kTxFirstByteAndAddressLength{1 + kAddressLength};
                        const Bytes tx_envelope{tx_buffer.substr(kTxFirstByteAndAddressLength)};
                        ByteView tx_envelope_view{tx_envelope};

                        rlp::Header tx_header;
                        TransactionType tx_type;
                        decode_result = rlp::decode_transaction_header_and_type(tx_envelope_view, tx_header, tx_type);
                        if (!decode_result) {
                            SILK_ERROR << "cannot decode tx envelope: " << to_hex(tx_envelope) << " i: " << i << " error: " << magic_enum::enum_name(decode_result.error());
                            return false;
                        }
                        const std::size_t tx_payload_offset = tx_type == TransactionType::kLegacy ? 0 : (tx_envelope.length() - tx_header.payload_length);

                        if (i % 100'000 == 0) {
                            SILK_DEBUG << "header.list: " << tx_header.list << " header.payload_length: " << tx_header.payload_length << " i: " << i;
                        }

                        const Bytes tx_payload{tx_buffer.substr(kTxFirstByteAndAddressLength + tx_payload_offset)};
                        const auto h256{keccak256(tx_payload)};
                        std::copy(std::begin(h256.bytes), std::begin(h256.bytes) + kHashLength, std::begin(tx_hash.bytes));
                        SILK_DEBUG << "type: " << int(tx_type) << " i: " << i << " payload: " << to_hex(tx_payload)
                                   << " h256: " << to_hex(h256.bytes, kHashLength);
                        tx_hash_rs.add_key(tx_hash.bytes, kHashLength, offset);
                        tx_hash_to_block_rs.add_key(tx_hash.bytes, kHashLength, block_number);
                    }

                    ++i;
                    offset = next_position;
                    tx_buffer.clear();
                }

                if (i != expected_tx_count) {
                    throw std::runtime_error{"tx count mismatch: expected=" + std::to_string(expected_tx_count) +
                                             " got=" + std::to_string(i)};
                }

                return true;
            });
        if (!read_ok) throw std::runtime_error{"cannot build index for: " + segment_path_.path().string()};

        SILK_TRACE << "Build tx_hash RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected = tx_hash_rs.build();
        SILK_TRACE << "Build tx_hash RecSplit index collision_detected: " << collision_detected << " [" << iterations << "]";

        SILK_TRACE << "Build tx_hash_2_bn RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected |= tx_hash_to_block_rs.build();
        SILK_TRACE << "Build tx_hash_2_bn RecSplit index collision_detected: " << collision_detected << " [" << iterations << "]";

        if (collision_detected) {
            tx_hash_rs.reset_new_salt();
            tx_hash_to_block_rs.reset_new_salt();
        }
    } while (collision_detected);
    SILK_TRACE << "Build index for: " << segment_path_.path().string() << " end [iterations=" << iterations << "]";

    SILK_TRACE << "TransactionIndex::build path: " << segment_path_.path().string() << " end";
}

bool TransactionIndex::walk(RecSplit8& /*rec_split*/, uint64_t /*i*/, uint64_t /*offset*/, ByteView /*word*/) {
    return true;
}

}  // namespace silkworm::snapshot
