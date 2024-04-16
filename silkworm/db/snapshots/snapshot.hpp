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

#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/snapshots/path.hpp>
#include <silkworm/db/snapshots/rec_split/rec_split_par.hpp>
#include <silkworm/db/snapshots/seg/decompressor.hpp>
#include <silkworm/infra/common/os.hpp>

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

//! \brief Generic snapshot containing data points for a specific block interval [block_from, block_to).
//! \warning The snapshot segment can also be externally managed. This means that the memory-mapping can happen
//! outside of this class and a \code Snapshot instance can be created by specifying the \code MemoryMappedRegion
//! segment containing the information about the memory region already mapped. This must be taken into account
//! because we must avoid to memory-map it again.
class Snapshot {
  public:
    static inline const auto kPageSize{os::page_size()};

    explicit Snapshot(SnapshotPath path, std::optional<MemoryMappedRegion> segment_region = std::nullopt);
    virtual ~Snapshot() = default;

    [[nodiscard]] SnapshotPath path() const { return path_; }
    [[nodiscard]] std::filesystem::path fs_path() const { return path_.path(); }

    [[nodiscard]] BlockNum block_from() const { return path_.block_from(); }
    [[nodiscard]] BlockNum block_to() const { return path_.block_to(); }

    [[nodiscard]] bool empty() const { return item_count() == 0; }
    [[nodiscard]] std::size_t item_count() const { return decoder_.words_count(); }

    [[nodiscard]] MemoryMappedRegion memory_file_region() const;

    void reopen_segment();
    virtual void reopen_index() = 0;

    struct WordItem {
        uint64_t position{0};
        uint64_t offset{0};
        Bytes value;

        WordItem() {
            value.reserve(kPageSize);
        }
    };
    using WordItemFunc = std::function<bool(WordItem&)>;
    bool for_each_item(const WordItemFunc& fn);
    [[nodiscard]] std::optional<WordItem> next_item(uint64_t offset, ByteView prefix = {}) const;

    void close();

  protected:
    void close_segment();
    virtual void close_index() = 0;

    //! The path of the segment file for this snapshot
    SnapshotPath path_;

    seg::Decompressor decoder_;
};

class HeaderSnapshot : public Snapshot {
  public:
    explicit HeaderSnapshot(SnapshotPath path);
    HeaderSnapshot(SnapshotPath path, MappedHeadersSnapshot mapped);
    ~HeaderSnapshot() override;

    [[nodiscard]] const rec_split::RecSplitIndex* idx_header_hash() const { return idx_header_hash_.get(); }

    using Walker = std::function<bool(const BlockHeader* header)>;
    bool for_each_header(const Walker& walker);
    [[nodiscard]] std::optional<BlockHeader> next_header(uint64_t offset, std::optional<Hash> hash = {}) const;

    [[nodiscard]] std::optional<BlockHeader> header_by_hash(const Hash& block_hash) const;
    [[nodiscard]] std::optional<BlockHeader> header_by_number(BlockNum block_height) const;

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

    using Walker = std::function<bool(BlockNum number, const StoredBlockBody* body)>;
    bool for_each_body(const Walker& walker);
    [[nodiscard]] std::optional<StoredBlockBody> next_body(uint64_t offset) const;

    std::pair<uint64_t, uint64_t> compute_txs_amount();

    [[nodiscard]] std::optional<StoredBlockBody> body_by_number(BlockNum block_height) const;

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

    [[nodiscard]] std::optional<Transaction> next_txn(uint64_t offset, std::optional<Hash> hash = {}) const;

    [[nodiscard]] std::optional<Transaction> txn_by_hash(const Hash& txn_hash) const;
    [[nodiscard]] std::optional<Transaction> txn_by_id(uint64_t txn_id) const;
    [[nodiscard]] std::vector<Transaction> txn_range(uint64_t base_txn_id, uint64_t txn_count, bool read_senders) const;
    [[nodiscard]] std::vector<Bytes> txn_rlp_range(uint64_t base_txn_id, uint64_t txn_count) const;

    [[nodiscard]] std::optional<BlockNum> block_num_by_txn_hash(const Hash& txn_hash) const;

    void reopen_index() override;

  protected:
    static std::pair<ByteView, ByteView> slice_tx_data(const WordItem& item);
    static DecodingResult decode_txn(const WordItem& item, Transaction& tx);

    using Walker = std::function<bool(uint64_t i, ByteView senders_data, ByteView txn_rlp)>;
    void for_each_txn(uint64_t base_txn_id, uint64_t txn_count, const Walker& walker) const;

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
