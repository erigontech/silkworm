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

#include "snapshot.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm::snapshot {

namespace fs = std::filesystem;

Snapshot::Snapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
    : path_(std::move(path)), block_from_(block_from), block_to_(block_to), decoder_{path_} {
    if (block_to < block_from) {
        throw std::logic_error{"invalid block range: block_to less than block_from"};
    }
}

void Snapshot::reopen_segment() {
    close_segment();
    // TODO(canepat) consider extracting MemoryMappedFile from Decompressor and keep it here
    // TODO(canepat) so that we open/close the file more explicitly and wrap Decompressor around it
    // Open decompressor that in turn opens mapped file
    decoder_.open();
}

bool Snapshot::for_each_item(const Snapshot::WordItemFunc& fn) {
    return decoder_.read_ahead([fn](huffman::Decompressor::Iterator it) -> bool {
        uint64_t word_count{0};
        WordItem item{};
        while (it.has_next()) {
            const uint64_t next_offset = it.next(item.value);
            item.position = word_count;
            SILK_DEBUG << "for_each_item item: offset=" << item.offset << " position=" << item.position
                       << " value=" << to_hex(item.value);
            const bool result = fn(item);
            if (!result) return false;
            ++word_count;
            item.offset = next_offset;
            item.value.clear();
        }
        return true;
    });
}

void Snapshot::close() {
    close_segment();
    close_index();
}

void Snapshot::close_segment() {
    // Close decompressor that in turn closes mapped file
    decoder_.close();
}

SnapshotPath HeaderSnapshot::path() const {
    return SnapshotPath::from(path_.parent_path(), kSnapshotV1, block_from_, block_to_, SnapshotType::headers);
}

bool HeaderSnapshot::for_each_header(const Walker& walker) {
    return for_each_item([walker](const WordItem& item) -> bool {
        ByteView encoded_header{item.value.data() + 1, item.value.length() - 1};
        SILK_DEBUG << "for_each_header encoded_header: " << to_hex(encoded_header);
        BlockHeader header;
        const auto decode_result = rlp::decode(encoded_header, header);
        if (!decode_result) {
            SILK_DEBUG << "for_each_header decode_result error: " << magic_enum::enum_name(decode_result.error());
            return false;
        }
        SILK_DEBUG << "for_each_header header number: " << header.number << " hash:" << to_hex(header.hash());
        return walker(&header);
    });
}

void HeaderSnapshot::reopen_index() {
    close_index();

    const auto header_index_path = path().index_file();
    if (header_index_path.exists()) {
        idx_header_hash_ = std::make_unique<succinct::RecSplitIndex>(header_index_path.path());
        if (idx_header_hash_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            close_index();
        }
    }
}

void HeaderSnapshot::close_index() {
    idx_header_hash_.reset();
}

SnapshotPath BodySnapshot::path() const {
    return SnapshotPath::from(path_.parent_path(), kSnapshotV1, block_from_, block_to_, SnapshotType::bodies);
}

bool BodySnapshot::for_each_body(const Walker& walker) {
    return for_each_item([&](const WordItem& item) -> bool {
        const BlockNum number = block_from_ + item.position;
        ByteView body_rlp{item.value.data(), item.value.length()};
        SILK_DEBUG << "for_each_body number: " << number << " body_rlp: " << to_hex(body_rlp);
        db::detail::BlockBodyForStorage body = db::detail::decode_stored_block_body(body_rlp);
        SILK_DEBUG << "for_each_body number: " << number << " txn_count: " << body.txn_count << " base_txn_id:" << body.base_txn_id;
        return walker(number, &body);
    });
}

std::pair<uint64_t, uint64_t> BodySnapshot::compute_txs_amount() {
    uint64_t first_tx_id{0}, last_tx_id{0}, last_txs_amount{0};

    const bool read_ok = for_each_body([&](BlockNum number, const db::detail::BlockBodyForStorage* body) {
        if (number == block_from_) {
            first_tx_id = body->base_txn_id;
        }
        if (number == block_to_ - 1) {
            last_tx_id = body->base_txn_id;
            last_txs_amount = body->txn_count;
        }
        return true;
    });
    if (!read_ok) throw std::runtime_error{"error computing txs amount in: " + path_.string()};
    if (first_tx_id == 0 && last_tx_id == 0) throw std::runtime_error{"empty body snapshot: " + path_.string()};

    SILK_DEBUG << "first_tx_id: " << first_tx_id << " last_tx_id: " << last_tx_id << " last_txs_amount: " << last_txs_amount;

    return {first_tx_id, last_tx_id + last_txs_amount - first_tx_id};
}

void BodySnapshot::reopen_index() {
    close_index();

    const auto body_index_path = path().index_file();
    if (body_index_path.exists()) {
        idx_body_number_ = std::make_unique<succinct::RecSplitIndex>(body_index_path.path());
        if (idx_body_number_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            close_index();
        }
    }
}

void BodySnapshot::close_index() {
    idx_body_number_.reset();
}

SnapshotPath TransactionSnapshot::path() const {
    return SnapshotPath::from(path_.parent_path(), kSnapshotV1, block_from_, block_to_, SnapshotType::transactions);
}

void TransactionSnapshot::reopen_index() {
    close_index();

    const auto tx_hash_index_path = path().index_file_for_type(SnapshotType::transactions);
    if (tx_hash_index_path.exists()) {
        idx_txn_hash_ = std::make_unique<succinct::RecSplitIndex>(tx_hash_index_path.path());
        if (idx_txn_hash_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            close_index();
        }
    }

    const auto tx_hash_2_block_index_path = path().index_file_for_type(SnapshotType::transactions2block);
    if (tx_hash_2_block_index_path.exists()) {
        idx_txn_hash_2_block_ = std::make_unique<succinct::RecSplitIndex>(tx_hash_2_block_index_path.path());
        if (idx_txn_hash_2_block_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            close_index();
        }
    }
}

void TransactionSnapshot::close_index() {
    idx_txn_hash_.reset();
    idx_txn_hash_2_block_.reset();
}

}  // namespace silkworm::snapshot
