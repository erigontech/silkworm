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

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <utility>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/rec_split/rec_split_par.hpp>

#include "snapshot_reader.hpp"
#include "snapshot_word_serializer.hpp"

namespace silkworm::snapshots {

struct MappedHeadersSnapshot {
    MemoryMappedRegion segment;
    MemoryMappedRegion header_hash_index;
};

struct MappedBodiesSnapshot {
    MemoryMappedRegion segment;
    MemoryMappedRegion block_num_index;
};

struct MappedTransactionsSnapshot {
    MemoryMappedRegion segment;
    MemoryMappedRegion tx_hash_index;
    MemoryMappedRegion tx_hash_2_block_index;
};

class HeaderSnapshot : public Snapshot {
  public:
    explicit HeaderSnapshot(SnapshotPath path);
    HeaderSnapshot(SnapshotPath path, MappedHeadersSnapshot mapped);
    ~HeaderSnapshot() override;

    [[nodiscard]] const rec_split::RecSplitIndex* idx_header_hash() const { return idx_header_hash_.get(); }

    void reopen_index() override;

  protected:
    void close_index() override;

  private:
    //! Index header_hash -> headers_segment_offset
    std::unique_ptr<rec_split::RecSplitIndex> idx_header_hash_;

    //! The external memory-mapped region for Headers snapshot index
    std::optional<MemoryMappedRegion> idx_header_hash_region_;
};

using StoredBlockBody = BlockBodyForStorage;

class BodySnapshot : public Snapshot {
  public:
    explicit BodySnapshot(SnapshotPath path, std::optional<MemoryMappedRegion> segment_region = std::nullopt);
    BodySnapshot(SnapshotPath path, MappedBodiesSnapshot mapped);
    ~BodySnapshot() override;

    [[nodiscard]] const rec_split::RecSplitIndex* idx_body_number() const { return idx_body_number_.get(); }

    void reopen_index() override;

  protected:
    void close_index() override;

  private:
    //! Index block_num_u64 -> bodies_segment_offset
    std::unique_ptr<rec_split::RecSplitIndex> idx_body_number_;

    //! The external memory-mapped region for Bodies snapshot index
    std::optional<MemoryMappedRegion> idx_body_number_region_;
};

class TransactionSnapshot : public Snapshot {
  public:
    explicit TransactionSnapshot(SnapshotPath path);
    TransactionSnapshot(SnapshotPath path, MappedTransactionsSnapshot mapped);
    ~TransactionSnapshot() override;

    [[nodiscard]] const rec_split::RecSplitIndex* idx_txn_hash() const { return idx_txn_hash_.get(); }
    [[nodiscard]] const rec_split::RecSplitIndex* idx_txn_hash_2_block() const { return idx_txn_hash_2_block_.get(); }

    void reopen_index() override;

  protected:
    void close_index() override;

  private:
    //! Index transaction_hash -> transactions_segment_offset
    std::unique_ptr<rec_split::RecSplitIndex> idx_txn_hash_;

    //! Index transaction_hash -> block_number
    std::unique_ptr<rec_split::RecSplitIndex> idx_txn_hash_2_block_;

    //! The external memory-mapped region for Transactions hash->offset index
    std::optional<MemoryMappedRegion> idx_txn_hash_region_;

    //! The external memory-mapped region for Transactions hash->block_number index
    std::optional<MemoryMappedRegion> idx_txn_hash_2_block_region_;
};

}  // namespace silkworm::snapshots
