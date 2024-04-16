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

#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/log.hpp>

#include "body_snapshot.hpp"
#include "header_snapshot.hpp"
#include "txn_snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

HeaderSnapshot::HeaderSnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

HeaderSnapshot::HeaderSnapshot(SnapshotPath path, MappedHeadersSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment), idx_header_hash_region_{mapped.header_hash_index} {}

HeaderSnapshot::~HeaderSnapshot() {
    close();
}

bool HeaderSnapshot::for_each_header(const Walker& walker) {
    for (auto it = begin(std::make_shared<HeaderSnapshotWordSerializer>()); it != end(); ++it) {
        auto s = dynamic_cast<HeaderSnapshotWordSerializer&>(**it);
        const bool go_on = walker(&s.header);
        if (!go_on) return false;
    }
    return true;
}

std::optional<BlockHeader> HeaderSnapshot::next_header(uint64_t offset, std::optional<Hash> hash) const {
    HeaderSnapshotWordSerializer serializer;

    // Get the next data item at specified offset, optionally checking if it starts with block hash first byte
    const auto item = hash ? next_item(offset, {hash->bytes, 1}) : next_item(offset);
    if (!item) {
        return std::nullopt;
    }

    try {
        serializer.decode_word(item->value);
    } catch (...) {
        return std::nullopt;
    }
    serializer.check_sanity_with_metadata(path_.block_from(), path_.block_to());
    return serializer.header;
}

std::optional<BlockHeader> HeaderSnapshot::header_by_hash(const Hash& block_hash) const {
    if (!idx_header_hash_) {
        return {};
    }

    // First, get the header ordinal position in snapshot by using block hash as MPHF index
    const auto [block_header_position, found] = idx_header_hash_->lookup(block_hash);
    SILK_TRACE << "HeaderSnapshot::header_by_hash block_hash: " << block_hash.to_hex() << " block_header_position: "
               << block_header_position << " found: " << found;
    if (!found) {
        return {};
    }
    // Then, get the header offset in snapshot by using ordinal lookup
    const auto block_header_offset = idx_header_hash_->ordinal_lookup(block_header_position);
    SILK_TRACE << "HeaderSnapshot::header_by_hash block_header_offset: " << block_header_offset;
    // Finally, read the next header at specified offset
    auto header = next_header(block_header_offset, block_hash);
    // We *must* ensure that the retrieved header hash matches because there is no way to know if key exists in MPHF
    if (header && header->hash() != block_hash) {
        header.reset();
    }
    return header;
}

std::optional<BlockHeader> HeaderSnapshot::header_by_number(BlockNum block_height) const {
    if (!idx_header_hash_ || block_height < path_.block_from() || block_height >= path_.block_to()) {
        return {};
    }

    // First, calculate the header ordinal position relative to the first block height within snapshot
    const auto block_header_position = block_height - idx_header_hash_->base_data_id();
    // Then, get the header offset in snapshot by using ordinal lookup
    const auto block_header_offset = idx_header_hash_->ordinal_lookup(block_header_position);
    // Finally, read the next header at specified offset
    return next_header(block_header_offset);
}

void HeaderSnapshot::reopen_index() {
    ensure(decoder_.is_open(), "HeaderSnapshot: segment not open, call reopen_segment");

    close_index();

    const auto header_index_path = path().index_file();
    if (header_index_path.exists()) {
        idx_header_hash_ = std::make_unique<rec_split::RecSplitIndex>(header_index_path.path(), idx_header_hash_region_);
        if (idx_header_hash_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(header_index_path.path());
            ensure(removed, "HeaderSnapshot: cannot remove index file");
            close_index();
        }
    }
}

void HeaderSnapshot::close_index() {
    idx_header_hash_.reset();
}

BodySnapshot::BodySnapshot(SnapshotPath path, std::optional<MemoryMappedRegion> segment_region)
    : Snapshot(std::move(path), segment_region) {}

BodySnapshot::BodySnapshot(SnapshotPath path, MappedBodiesSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment), idx_body_number_region_{mapped.block_num_index} {}

BodySnapshot::~BodySnapshot() {
    close();
}

bool BodySnapshot::for_each_body(const Walker& walker) {
    BodySnapshotWordSerializer serializer;

    return for_each_item([&](const WordItem& item) -> bool {
        serializer.decode_word(item.value);
        serializer.check_sanity_with_metadata(path_.block_from(), path_.block_to());
        const BlockNum number = path_.block_from() + item.position;
        return walker(number, &serializer.body);
    });
}

std::pair<uint64_t, uint64_t> BodySnapshot::compute_txs_amount() {
    uint64_t first_tx_id{0}, last_tx_id{0}, last_txs_amount{0};

    const bool read_ok = for_each_body([&](BlockNum number, const StoredBlockBody* body) {
        if (number == path_.block_from()) {
            first_tx_id = body->base_txn_id;
        }
        if (number == path_.block_to() - 1) {
            last_tx_id = body->base_txn_id;
            last_txs_amount = body->txn_count;
        }
        return true;
    });
    if (!read_ok) throw std::runtime_error{"error computing txs amount in: " + path_.path().string()};
    if (first_tx_id == 0 && last_tx_id == 0) throw std::runtime_error{"empty body snapshot: " + path_.path().string()};

    SILK_TRACE << "first_tx_id: " << first_tx_id << " last_tx_id: " << last_tx_id << " last_txs_amount: " << last_txs_amount;

    return {first_tx_id, last_tx_id + last_txs_amount - first_tx_id};
}

std::optional<StoredBlockBody> BodySnapshot::next_body(uint64_t offset) const {
    BodySnapshotWordSerializer serializer;

    const auto item = next_item(offset);
    if (!item) {
        return std::nullopt;
    }

    try {
        serializer.decode_word(item->value);
    } catch (...) {
        return std::nullopt;
    }
    serializer.check_sanity_with_metadata(path_.block_from(), path_.block_to());

    ensure(serializer.body.base_txn_id >= idx_body_number_->base_data_id(),
           [&]() { return path().index_file().filename() + " has wrong base data ID for base txn ID: " + std::to_string(serializer.body.base_txn_id); });
    return serializer.body;
}

std::optional<StoredBlockBody> BodySnapshot::body_by_number(BlockNum block_height) const {
    if (!idx_body_number_ || block_height < idx_body_number_->base_data_id()) {
        return {};
    }

    // First, calculate the body ordinal position relative to the first block height within snapshot
    const auto block_body_position = block_height - idx_body_number_->base_data_id();
    // Then, get the body offset in snapshot by using ordinal lookup
    const auto block_body_offset = idx_body_number_->ordinal_lookup(block_body_position);
    // Finally, read the next body at specified offset
    return next_body(block_body_offset);
}

void BodySnapshot::reopen_index() {
    ensure(decoder_.is_open(), "BodySnapshot: segment not open, call reopen_segment");

    close_index();

    const auto body_index_path = path().index_file();
    if (body_index_path.exists()) {
        idx_body_number_ = std::make_unique<rec_split::RecSplitIndex>(body_index_path.path(), idx_body_number_region_);
        if (idx_body_number_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(body_index_path.path());
            ensure(removed, "BodySnapshot: cannot remove index file");
            close_index();
        }
    }
}

void BodySnapshot::close_index() {
    idx_body_number_.reset();
}

TransactionSnapshot::TransactionSnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

TransactionSnapshot::TransactionSnapshot(SnapshotPath path, MappedTransactionsSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment),
      idx_txn_hash_region_{mapped.tx_hash_index},
      idx_txn_hash_2_block_region_{mapped.tx_hash_2_block_index} {}

TransactionSnapshot::~TransactionSnapshot() {
    close();
}

[[nodiscard]] std::optional<Transaction> TransactionSnapshot::next_txn(uint64_t offset, std::optional<Hash> hash) const {
    TransactionSnapshotWordSerializer serializer;

    // Get the next data item at specified offset, optionally checking if it starts with txn hash first byte
    const auto item = hash ? next_item(offset, {hash->bytes, 1}) : next_item(offset);
    if (!item) {
        return std::nullopt;
    }

    try {
        serializer.decode_word(item->value);
    } catch (...) {
        return std::nullopt;
    }
    serializer.check_sanity_with_metadata(path_.block_from(), path_.block_to());
    return serializer.transaction;
}

std::optional<Transaction> TransactionSnapshot::txn_by_hash(const Hash& txn_hash) const {
    if (!idx_txn_hash_) {
        return {};
    }

    // First, get the transaction ordinal position in snapshot by using block hash as MPHF index
    const auto [txn_position, found] = idx_txn_hash_->lookup(txn_hash);
    if (!found) {
        return {};
    }
    // Then, get the transaction offset in snapshot by using ordinal lookup
    const auto txn_offset = idx_txn_hash_->ordinal_lookup(txn_position);
    // Finally, read the next transaction at specified offset
    auto txn = next_txn(txn_offset, txn_hash);
    // We *must* ensure that the retrieved txn hash matches because there is no way to know if key exists in MPHF
    if (txn && txn->hash() != txn_hash) {
        return {};
    }
    return txn;
}

std::optional<Transaction> TransactionSnapshot::txn_by_id(uint64_t txn_id) const {
    if (!idx_txn_hash_) {
        return {};
    }

    // First, calculate the transaction ordinal position relative to the first transaction ID within snapshot
    const auto txn_position = txn_id - idx_txn_hash_->base_data_id();
    // Then, get the transaction offset in snapshot by using ordinal lookup
    const auto txn_offset = idx_txn_hash_->ordinal_lookup(txn_position);
    // Finally, read the next transaction at specified offset
    return next_txn(txn_offset);
}

std::optional<BlockNum> TransactionSnapshot::block_num_by_txn_hash(const Hash& txn_hash) const {
    if (!idx_txn_hash_2_block_) {
        return {};
    }

    // Lookup the block number using dedicated MPHF index
    const auto [block_number, found] = idx_txn_hash_2_block_->lookup(txn_hash);
    if (!found) {
        return {};
    }

    // Lookup the entire txn to check that the retrieved txn hash matches (no way to know if key exists in MPHF)
    const auto transaction{txn_by_hash(txn_hash)};
    if (!transaction) {
        return {};
    }

    return block_number;
}

std::vector<Transaction> TransactionSnapshot::txn_range(uint64_t base_txn_id, uint64_t txn_count, bool /*read_senders*/) const {
    TransactionSnapshotWordSerializer serializer;

    std::vector<Transaction> transactions;
    transactions.reserve(txn_count);

    for_each_txn(base_txn_id, txn_count, [&transactions, &serializer, this](ByteView word) -> bool {
        serializer.decode_word(word);
        serializer.check_sanity_with_metadata(path_.block_from(), path_.block_to());
        transactions.push_back(std::move(serializer.transaction));
        return true;
    });

    return transactions;
}

std::vector<Bytes> TransactionSnapshot::txn_rlp_range(uint64_t base_txn_id, uint64_t txn_count) const {
    TransactionSnapshotWordPayloadRlpSerializer serializer;

    std::vector<Bytes> rlp_txs;
    rlp_txs.reserve(txn_count);

    for_each_txn(base_txn_id, txn_count, [&rlp_txs, &serializer, this](ByteView word) -> bool {
        serializer.decode_word(word);
        serializer.check_sanity_with_metadata(path_.block_from(), path_.block_to());
        rlp_txs.emplace_back(serializer.tx_payload);
        return true;
    });

    return rlp_txs;
}

void TransactionSnapshot::for_each_txn(uint64_t base_txn_id, uint64_t txn_count, const Walker& walker) const {
    if (!idx_txn_hash_ || txn_count == 0) {
        return;
    }

    ensure(base_txn_id >= idx_txn_hash_->base_data_id(),
           [&]() { return path().index_file().filename() + " has wrong base data ID for base txn ID: " + std::to_string(base_txn_id); });

    // First, calculate the first transaction ordinal position relative to the base transaction within snapshot
    const auto first_txn_position = base_txn_id - idx_txn_hash_->base_data_id();

    // Then, get the first transaction offset in snapshot by using ordinal lookup
    const auto first_txn_offset = idx_txn_hash_->ordinal_lookup(first_txn_position);

    // Finally, iterate over each encoded transaction item
    for (uint64_t i{0}, offset{first_txn_offset}; i < txn_count; ++i) {
        const auto item = next_item(offset);
        ensure(item.has_value(), [&]() { return "TransactionSnapshot: record not found at offset=" + std::to_string(offset); });

        const bool go_on = walker(item->value);
        if (!go_on) return;

        offset = item->offset;
    }
}

void TransactionSnapshot::reopen_index() {
    ensure(decoder_.is_open(), "TransactionSnapshot: segment not open, call reopen_segment");

    close_index();

    const auto tx_hash_index_path = path().index_file_for_type(SnapshotType::transactions);
    if (tx_hash_index_path.exists()) {
        idx_txn_hash_ = std::make_unique<rec_split::RecSplitIndex>(tx_hash_index_path.path(), idx_txn_hash_region_);
        if (idx_txn_hash_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(tx_hash_index_path.path());
            ensure(removed, "TransactionSnapshot: cannot remove tx_hash index file");
            close_index();
        }
    }

    const auto tx_hash_2_block_index_path = path().index_file_for_type(SnapshotType::transactions_to_block);
    if (tx_hash_2_block_index_path.exists()) {
        idx_txn_hash_2_block_ = std::make_unique<rec_split::RecSplitIndex>(tx_hash_2_block_index_path.path(), idx_txn_hash_2_block_region_);
        if (idx_txn_hash_2_block_->last_write_time() < decoder_.last_write_time()) {
            // Index has been created before the segment file, needs to be ignored (and rebuilt) as inconsistent
            const bool removed = std::filesystem::remove(tx_hash_2_block_index_path.path());
            ensure(removed, "TransactionSnapshot: cannot remove tx_hash_2_block index file");
            close_index();
        }
    }
}

void TransactionSnapshot::close_index() {
    idx_txn_hash_.reset();
    idx_txn_hash_2_block_.reset();
}

}  // namespace silkworm::snapshots
