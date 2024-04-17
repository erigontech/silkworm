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
#include "txn_snapshot.hpp"
#include "txn_snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

HeaderSnapshot::HeaderSnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

HeaderSnapshot::HeaderSnapshot(SnapshotPath path, MappedHeadersSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment), idx_header_hash_region_{mapped.header_hash_index} {}

HeaderSnapshot::~HeaderSnapshot() {
    close();
}

std::optional<BlockHeader> HeaderSnapshot::header_by_hash(const Hash& block_hash) const {
    if (!idx_header_hash_) {
        return {};
    }

    auto block_header_offset_opt = idx_header_hash_->ordinal_lookup_by_key(block_hash);
    if (!block_header_offset_opt) {
        return std::nullopt;
    }
    size_t block_header_offset = *block_header_offset_opt;
    SILK_TRACE << "HeaderSnapshot::header_by_hash block_header_offset: " << block_header_offset;
    // Finally, read the next header at specified offset
    auto header = HeaderSnapshotReader{*this}.seek_one(block_header_offset, block_hash);
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

    size_t block_header_offset = idx_header_hash_->ordinal_lookup_by_data_id(block_height);
    return HeaderSnapshotReader{*this}.seek_one(block_header_offset);
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

std::pair<uint64_t, uint64_t> BodySnapshot::compute_txs_amount() {
    uint64_t first_tx_id{0}, last_tx_id{0}, last_txs_amount{0};
    BlockNum number = path_.block_from();

    BodySnapshotReader reader{*this};
    for (auto& body : reader) {
        if (number == path_.block_from()) {
            first_tx_id = body.base_txn_id;
        }
        if (number == path_.block_to() - 1) {
            last_tx_id = body.base_txn_id;
            last_txs_amount = body.txn_count;
        }
        number++;
    }
    if (first_tx_id == 0 && last_tx_id == 0) throw std::runtime_error{"empty body snapshot: " + path_.path().string()};

    SILK_TRACE << "first_tx_id: " << first_tx_id << " last_tx_id: " << last_tx_id << " last_txs_amount: " << last_txs_amount;

    return {first_tx_id, last_tx_id + last_txs_amount - first_tx_id};
}

std::optional<StoredBlockBody> BodySnapshot::body_by_number(BlockNum block_height) const {
    if (!idx_body_number_ || block_height < idx_body_number_->base_data_id()) {
        return {};
    }

    size_t block_body_offset = idx_body_number_->ordinal_lookup_by_data_id(block_height);
    return BodySnapshotReader{*this}.seek_one(block_body_offset);
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

std::optional<Transaction> TransactionSnapshot::txn_by_hash(const Hash& txn_hash) const {
    if (!idx_txn_hash_) {
        return {};
    }

    auto txn_offset_opt = idx_txn_hash_->ordinal_lookup_by_key(txn_hash);
    if (!txn_offset_opt) {
        return std::nullopt;
    }
    size_t txn_offset = *txn_offset_opt;
    // Finally, read the next transaction at specified offset
    auto txn = TransactionSnapshotReader{*this}.seek_one(txn_offset, txn_hash);
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

    size_t txn_offset = idx_txn_hash_->ordinal_lookup_by_data_id(txn_id);
    return TransactionSnapshotReader{*this}.seek_one(txn_offset);
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

template <class TSnapshotReader>
struct RangeFromDataIdQuery {
    RangeFromDataIdQuery(
        const Snapshot& snapshot,
        const rec_split::RecSplitIndex& index)
        : snapshot_(snapshot),
          index_(index) {}

    std::vector<typename TSnapshotReader::Iterator::value_type> exec_into_vector(uint64_t first_data_id, uint64_t count) {
        size_t offset = index_.ordinal_lookup_by_data_id(first_data_id);
        return TSnapshotReader{snapshot_}.read_into_vector(offset, count);
    }

  private:
    const Snapshot& snapshot_;
    const rec_split::RecSplitIndex& index_;
};

std::vector<Transaction> TransactionSnapshot::txn_range(uint64_t first_txn_id, uint64_t count) const {
    if (!idx_txn_hash_) {
        return {};
    }
    RangeFromDataIdQuery<TransactionSnapshotReader> query{*this, *idx_txn_hash_};
    return query.exec_into_vector(first_txn_id, count);
}

std::vector<Bytes> TransactionSnapshot::txn_rlp_range(uint64_t first_txn_id, uint64_t count) const {
    if (!idx_txn_hash_) {
        return {};
    }
    RangeFromDataIdQuery<TransactionSnapshotPayloadRlpReader<Bytes>> query{*this, *idx_txn_hash_};
    return query.exec_into_vector(first_txn_id, count);
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
