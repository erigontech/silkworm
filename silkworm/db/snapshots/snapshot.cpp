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

namespace silkworm::snapshots {

HeaderSnapshot::HeaderSnapshot(SnapshotPath path) : Snapshot(std::move(path)) {}

HeaderSnapshot::HeaderSnapshot(SnapshotPath path, MappedHeadersSnapshot mapped)
    : Snapshot(std::move(path), mapped.segment), idx_header_hash_region_{mapped.header_hash_index} {}

HeaderSnapshot::~HeaderSnapshot() {
    close();
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
