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
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>
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

std::optional<Snapshot::WordItem> Snapshot::next_item(uint64_t offset) const {
    auto data_iterator = decoder_.make_iterator();
    data_iterator.reset(offset);

    std::optional<WordItem> item;
    if (!data_iterator.has_next()) {
        return item;
    }
    item = WordItem{};
    item->offset = data_iterator.next(item->value);
    return item;
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
    return for_each_item([this, walker](const WordItem& item) -> bool {
        BlockHeader header;
        const auto decode_ok = decode_header(item, header);
        if (!decode_ok) {
            return false;
        }
        return walker(&header);
    });
}

std::optional<BlockHeader> HeaderSnapshot::next_header(uint64_t offset) const {
    const auto item = next_item(offset);
    std::optional<BlockHeader> header;
    if (!item) {
        return header;
    }
    header = BlockHeader{};
    const auto decode_ok = decode_header(*item, *header);
    if (!decode_ok) {
        return {};
    }
    return header;
}

std::optional<BlockHeader> HeaderSnapshot::header_by_hash(const Hash& block_hash) const {
    // First, get the header ordinal position in snapshot by using block hash as MPHF index
    const auto block_header_position = idx_header_hash_->lookup(block_hash);
    // Then, get the header offset in snapshot by using ordinal lookup
    const auto block_header_offset = idx_header_hash_->ordinal_lookup(block_header_position);
    // Finally, read the next header at specified offset
    return next_header(block_header_offset);
}

std::optional<BlockHeader> HeaderSnapshot::header_by_number(BlockNum block_height) const {
    // First, calculate the header ordinal position relative to the first block height within snapshot
    const auto block_header_position = block_height - idx_header_hash_->base_data_id();
    // Then, get the header offset in snapshot by using ordinal lookup
    const auto block_header_offset = idx_header_hash_->ordinal_lookup(block_header_position);
    // Finally, read the next header at specified offset
    return next_header(block_header_offset);
}

bool HeaderSnapshot::decode_header(const Snapshot::WordItem& item, BlockHeader& header) const {
    // Skip first byte in data as it is encoding start tag.
    ByteView encoded_header{item.value.data() + 1, item.value.length() - 1};
    SILK_TRACE << "decode_header number: " << (block_from_ + item.position) << " encoded_header: " << to_hex(encoded_header);
    const auto decode_result = rlp::decode(encoded_header, header);
    if (!decode_result) {
        SILK_TRACE << "decode_header number: " << (block_from_ + item.position) << " error: " << magic_enum::enum_name(decode_result.error());
        return false;
    }
    SILKWORM_ASSERT(header.number == (block_from_ + item.position));
    SILK_TRACE << "decode_header header number: " << header.number << " hash:" << to_hex(header.hash());
    return true;
}

void HeaderSnapshot::reopen_index() {
    ensure(decoder_.is_open(), "HeaderSnapshot::reopen_index segment not open: call reopen_segment");

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
        db::detail::BlockBodyForStorage body;
        success_or_throw(decode_body(item, body));
        const BlockNum number = block_from_ + item.position;
        return walker(number, &body);
    });
}

std::pair<uint64_t, uint64_t> BodySnapshot::compute_txs_amount() {
    uint64_t first_tx_id{0}, last_tx_id{0}, last_txs_amount{0};

    const bool read_ok = for_each_body([&](BlockNum number, const StoredBlockBody* body) {
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

std::optional<StoredBlockBody> BodySnapshot::next_body(uint64_t offset) const {
    const auto item = next_item(offset);
    std::optional<StoredBlockBody> stored_body;
    if (!item) {
        return stored_body;
    }
    stored_body = StoredBlockBody{};
    const auto decode_ok = decode_body(*item, *stored_body);
    if (!decode_ok) {
        return {};
    }
    return stored_body;
}

std::optional<StoredBlockBody> BodySnapshot::stored_body_by_number(BlockNum block_height) const {
    // First, calculate the body ordinal position relative to the first block height within snapshot
    const auto block_body_position = block_height - idx_body_number_->base_data_id();
    // Then, get the body offset in snapshot by using ordinal lookup
    const auto block_body_offset = idx_body_number_->ordinal_lookup(block_body_position);
    // Finally, read the next body at specified offset
    return next_body(block_body_offset);
}

DecodingResult BodySnapshot::decode_body(const Snapshot::WordItem& item, StoredBlockBody& body) const {
    ByteView body_rlp{item.value.data(), item.value.length()};
    SILK_TRACE << "decode_body number: " << (block_from_ + item.position) << " body_rlp: " << to_hex(body_rlp);
    const auto result = db::detail::decode_stored_block_body(body_rlp, body);
    SILK_TRACE << "decode_body number: " << (block_from_ + item.position) << " txn_count: " << body.txn_count << " base_txn_id:" << body.base_txn_id;
    return result;
}

void BodySnapshot::reopen_index() {
    ensure(decoder_.is_open(), "BodySnapshot::reopen_index segment not open: call reopen_segment");

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

[[nodiscard]] std::optional<Transaction> TransactionSnapshot::next_txn(uint64_t offset) const {
    const auto item = next_item(offset);
    std::optional<Transaction> transaction;
    if (!item) {
        return transaction;
    }
    transaction = Transaction{};
    const auto decode_ok = decode_txn(*item, *transaction);
    if (!decode_ok) {
        return {};
    }
    return transaction;
}

std::optional<Transaction> TransactionSnapshot::txn_by_hash(const Hash& block_hash) const {
    // First, get the transaction ordinal position in snapshot by using block hash as MPHF index
    const auto txn_position = idx_txn_hash_->lookup(block_hash);
    // Then, get the transaction offset in snapshot by using ordinal lookup
    const auto txn_offset = idx_txn_hash_->ordinal_lookup(txn_position);
    // Finally, read the next transaction at specified offset
    return next_txn(txn_offset);
}

std::optional<Transaction> TransactionSnapshot::txn_by_id(uint64_t txn_id) const {
    // First, calculate the transaction ordinal position relative to the first block height within snapshot
    const auto txn_position = txn_id - idx_txn_hash_->base_data_id();
    // Then, get the transaction offset in snapshot by using ordinal lookup
    const auto txn_offset = idx_txn_hash_->ordinal_lookup(txn_position);
    // Finally, read the next transaction at specified offset
    return next_txn(txn_offset);
}

DecodingResult TransactionSnapshot::decode_txn(const Snapshot::WordItem& item, Transaction& tx) const {
    ByteView tx_rlp{item.value.data(), item.value.length()};
    SILK_TRACE << "decode_txn number: " << (block_from_ + item.position) << " tx_rlp: " << to_hex(tx_rlp);
    const auto result = rlp::decode(tx_rlp, tx);
    SILK_TRACE << "decode_txn number: " << (block_from_ + item.position);
    return result;
}

void TransactionSnapshot::reopen_index() {
    ensure(decoder_.is_open(), "TransactionSnapshot::reopen_index segment not open: call reopen_segment");

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
