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
#include <silkworm/node/recsplit/rec_split_seq.hpp>
#include <silkworm/node/test/snapshots.hpp>

namespace silkworm::snapshot {

struct Slice {
    uint64_t ordinal;
    uint64_t offset;
};

using ExtractOrdinal = std::function<uint64_t(Snapshot::WordItem&)>;

std::vector<Slice> prefetch_offsets(huffman::Decompressor& decoder, ExtractOrdinal extract_ordinal = nullptr) {
    std::vector<Slice> prefetched_offsets;
    uint64_t slice_size = decoder.words_count() / std::thread::hardware_concurrency();
    uint64_t last_slice = slice_size * (std::thread::hardware_concurrency() - 1);
    auto offsets = decoder.offset_range();
    Snapshot::for_each_item(decoder, offsets, 0, [&](Snapshot::WordItem& item) {
        if (item.position % slice_size == 0) {
            uint64_t ordinal = extract_ordinal ? extract_ordinal(item) : item.position;
            prefetched_offsets.push_back({.ordinal = ordinal, .offset = item.offset});
        }
        return item.position < last_slice;  // avoid processing last slice
    });
    if (prefetched_offsets.back().offset != decoder.data_size()) {
        prefetched_offsets.push_back({.ordinal = decoder.words_count(), .offset = offsets.end});
    }
    return prefetched_offsets;
}

using RecSplitSettings = succinct::RecSplitSettings;
using RecSplit8 = succinct::RecSplit8;

void Index::build(ThreadPool& thread_pool) {
    SILK_TRACE << "Index::build path: " << segment_path_.path().string() << " start";

    huffman::Decompressor decoder{segment_path_.path(), segment_region_};
    decoder.open();

    const SnapshotPath index_file = segment_path_.index_file();
    RecSplitSettings rec_split_settings{
        .keys_count = decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = index_file.path(),
        .base_data_id = index_file.block_from()};
    RecSplit8 rec_split{rec_split_settings, succinct::par_build_strategy(thread_pool)};

    SILK_TRACE << "Build index for: " << segment_path_.path().string() << " start";

    std::vector<Slice> prefetched_offsets = prefetch_offsets(decoder);

    uint64_t iterations{0};
    bool collision_detected{false};
    do {
        iterations++;
        std::atomic_bool read_ok{true};
        SILK_TRACE << "Process snapshot items to prepare index build for: " << segment_path_.path().string();

        for (size_t i = 0; i < prefetched_offsets.size() - 1; ++i) {
            uint64_t start_offset = prefetched_offsets[i].offset;
            uint64_t start_ordinal = prefetched_offsets[i].ordinal;
            uint64_t end_offset = prefetched_offsets[i + 1].offset;
            huffman::OffsetRange offset_range{start_offset, end_offset};

            thread_pool.push_task([&, start_offset, end_offset, start_ordinal]() {
                decoder.read_ahead(offset_range,
                   [start_offset, start_ordinal, &read_ok, &rec_split, this](huffman::Decompressor::Iterator it) {
                       // SILK_INFO << "offset: " << start_offset;
                       Bytes word{};
                       word.reserve(kPageSize);
                       uint64_t i{start_ordinal}, offset{start_offset};
                       while (it.has_next()) {
                           uint64_t next_position = it.next(word);
                           if (bool ok = walk(rec_split, i, offset, word); !ok) {
                               read_ok = false;
                               return false;
                           }
                           ++i;
                           offset = next_position;
                           word.clear();
                       }
                       return true;
                   });
            });
        }
        thread_pool.wait_for_tasks();

        if (!read_ok) throw std::runtime_error{"cannot build index for: " + segment_path_.path().string()};

        SILK_TRACE << "Build RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected = rec_split.build(thread_pool);
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
    rec_split.add_key(hash.bytes, kHashLength, offset, i);
    return true;
}

bool BodyIndex::walk(RecSplit8& rec_split, uint64_t i, uint64_t offset, ByteView /*word*/) {
    Bytes uint64_buffer;
    const auto size = test::encode_varint<uint64_t>(i, uint64_buffer);
    rec_split.add_key(uint64_buffer.data(), size, offset, i);
    return true;
}

void TransactionIndex::build(ThreadPool& thread_pool) {
    SILK_TRACE << "TransactionIndex::build path: " << segment_path_.path().string() << " start";

    const SnapshotPath bodies_segment_path = SnapshotPath::from(segment_path_.path().parent_path(),
                                                                segment_path_.version(),
                                                                segment_path_.block_from(),
                                                                segment_path_.block_to(),
                                                                SnapshotType::bodies);
    SILK_TRACE << "TransactionIndex::build bodies_segment path: " << bodies_segment_path.path().string();

    BodySnapshot bodies_snapshot{bodies_segment_path};
    bodies_snapshot.reopen_segment();

    huffman::Decompressor txs_decoder{segment_path_.path(), segment_region_};
    txs_decoder.open();

    std::vector<Slice> prefetched_offsets = prefetch_offsets(txs_decoder);

    uint64_t first_tx_id;
    uint64_t expected_tx_count;
    std::tie(first_tx_id, expected_tx_count) = bodies_snapshot.compute_txs_amount();

    SILK_TRACE << "TransactionIndex::build first_tx_id: " << first_tx_id << " expected_tx_count: " << expected_tx_count;

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
    RecSplit8 tx_hash_rs{tx_hash_rs_settings, succinct::par_build_strategy(thread_pool)};

    const SnapshotPath tx2block_idx_file = segment_path_.index_file_for_type(SnapshotType::transactions_to_block);
    SILK_TRACE << "TransactionIndex::build tx2block_idx_file path: " << tx2block_idx_file.path().string();
    RecSplitSettings tx_hash_to_block_rs_settings{
        .keys_count = txs_decoder.words_count(),
        .bucket_size = kBucketSize,
        .index_path = tx2block_idx_file.path(),
        .base_data_id = first_block_num,
        .double_enum_index = false};
    RecSplit8 tx_hash_to_block_rs{tx_hash_to_block_rs_settings, succinct::par_build_strategy(thread_pool)};

    huffman::Decompressor bodies_decoder{bodies_segment_path.path()};
    bodies_decoder.open();

    using DoubleReadAheadFunc = std::function<bool(huffman::Decompressor::Iterator, huffman::Decompressor::Iterator)>;
    auto double_read_ahead =
        [&txs_decoder, &bodies_decoder](huffman::OffsetRange offset_range, const DoubleReadAheadFunc& fn) -> bool {
        return txs_decoder.read_ahead(offset_range, [fn, &bodies_decoder](auto tx_it) -> bool {
            return bodies_decoder.read_ahead([fn, &tx_it](auto body_it) {
                return fn(tx_it, body_it);
            });
        });
    };

    SILK_TRACE << "Build index for: " << segment_path_.path().string() << " start";

    uint64_t iterations{0};
    Hash tx_hash;
    bool collision_detected{false};
    do {
        iterations++;
        std::atomic_bool read_ok{true};
        SILK_TRACE << "Process snapshot items to prepare index build for: " << segment_path_.path().string();
        for (size_t i = 0; i < prefetched_offsets.size() - 1; ++i) {
            uint64_t start_offset = prefetched_offsets[i].offset;
            uint64_t start_ordinal = prefetched_offsets[i].ordinal;
            uint64_t end_offset = prefetched_offsets[i + 1].offset;

            uint64_t start_block_num = first_block_num;

            thread_pool.push_task([&double_read_ahead, &tx_hash_rs, &tx_hash_to_block_rs, &read_ok,
                                    offset_range = huffman::OffsetRange(start_offset, end_offset),
                                    bn = start_block_num, f = first_tx_id, so = start_ordinal]() {
                bool ok = double_read_ahead(offset_range,
                    [&tx_hash_rs, &tx_hash_to_block_rs,
                     start_block_num = bn, first_tx_id = f, start_offset = offset_range.start, start_ordinal = so](auto tx_it, auto body_it) -> bool {
                        Hash tx_hash;
                        db::detail::BlockBodyForStorage body;
                        BlockNum block_number{start_block_num};

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

                        uint64_t i{start_ordinal}, offset{start_offset};
                        while (tx_it.has_next()) {
                            uint64_t next_position = tx_it.next(tx_buffer);
                            while (body.base_txn_id + body.txn_count <= first_tx_id + i) {
                                if (!body_it.has_next()) {
                                    SILK_ERROR << "body not found on block " << block_number;
                                    return false;
                                }
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

                                tx_hash_rs.add_key(tx_hash.bytes, kHashLength, offset, i);
                                tx_hash_to_block_rs.add_key(tx_hash.bytes, kHashLength, block_number, i);
                            } else {
                                // Skip tx hash first byte plus address length for transaction decoding
                                constexpr int kTxFirstByteAndAddressLength{1 + kAddressLength};
                                const Bytes tx_envelope{tx_buffer.substr(kTxFirstByteAndAddressLength)};  // todo(mike): avoid copy
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

                                const Bytes tx_payload{tx_buffer.substr(kTxFirstByteAndAddressLength + tx_payload_offset)};  // todo(mike): avoid copy
                                const auto h256{keccak256(tx_payload)};
                                std::copy(std::begin(h256.bytes), std::begin(h256.bytes) + kHashLength, std::begin(tx_hash.bytes));
                                // SILK_DEBUG << "type: " << int(tx_type) << " i: " << i << " payload: " << to_hex(tx_payload)
                                //            << " h256: " << to_hex(h256.bytes, kHashLength);
                                tx_hash_rs.add_key(tx_hash.bytes, kHashLength, offset, i);
                                tx_hash_to_block_rs.add_key(tx_hash.bytes, kHashLength, block_number, i);
                            }

                            ++i;
                            offset = next_position;
                            tx_buffer.clear();
                        }
                        // SILK_TRACE << " start_ordinal: " << start_ordinal << " end_ordinal(excl.): " << i
                        //            << " expected end_offset: " << end_offset << " actual end_offset " << offset
                        //            << " first block number: " << first_tx_id + start_ordinal << " last block number: " << block_number
                        //            << "\n";

                        // if (i != expected_tx_count) {
                        //     throw std::runtime_error{"tx count mismatch: expected=" + std::to_string(expected_tx_count) +
                        //                              " got=" + std::to_string(i)};
                        // }

                        return true;
                    });
                if (!ok) read_ok = false;
            });
        }
        thread_pool.wait_for_tasks();

        if (!read_ok) throw std::runtime_error{"cannot build index for: " + segment_path_.path().string()};

        SILK_TRACE << "Build tx_hash RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected = tx_hash_rs.build(thread_pool);
        SILK_TRACE << "Build tx_hash RecSplit index collision_detected: " << collision_detected << " [" << iterations << "]";

        SILK_TRACE << "Build tx_hash_2_bn RecSplit index for: " << segment_path_.path().string() << " [" << iterations << "]";
        collision_detected |= tx_hash_to_block_rs.build(thread_pool);
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
