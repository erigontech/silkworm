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
#include <silkworm/core/types/block.hpp>
#include <silkworm/node/db/util.hpp>
#include <silkworm/node/huffman/decompressor.hpp>
#include <silkworm/node/recsplit/rec_split.hpp>
#include <silkworm/node/snapshot/path.hpp>

namespace silkworm::snapshot {

class Snapshot {
  public:
    static constexpr uint64_t kPageSize{4096};

    explicit Snapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to);
    virtual ~Snapshot() = default;

    [[nodiscard]] virtual SnapshotPath path() const = 0;
    [[nodiscard]] std::filesystem::path fs_path() const { return path_; }

    [[nodiscard]] BlockNum block_from() const { return block_from_; }
    [[nodiscard]] BlockNum block_to() const { return block_to_; }

    [[nodiscard]] bool empty() const { return item_count() == 0; }
    [[nodiscard]] std::size_t item_count() const { return decoder_.words_count(); }

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

    std::filesystem::path path_;
    BlockNum block_from_{0};
    BlockNum block_to_{0};
    huffman::Decompressor decoder_;
};

class HeaderSnapshot : public Snapshot {
  public:
    explicit HeaderSnapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~HeaderSnapshot() override { close(); }

    [[nodiscard]] SnapshotPath path() const override;
    [[nodiscard]] const succinct::RecSplitIndex* idx_header_hash() const { return idx_header_hash_.get(); }

    using Walker = std::function<bool(const BlockHeader* header)>;
    bool for_each_header(const Walker& walker);
    [[nodiscard]] std::optional<BlockHeader> next_header(uint64_t offset, std::optional<Hash> hash = {}) const;

    [[nodiscard]] std::optional<BlockHeader> header_by_hash(const Hash& block_hash) const;
    [[nodiscard]] std::optional<BlockHeader> header_by_number(BlockNum block_height) const;

    void reopen_index() override;

  protected:
    bool decode_header(const Snapshot::WordItem& item, BlockHeader& header) const;

    void close_index() override;

  private:
    //! Index header_hash -> headers_segment_offset
    std::unique_ptr<succinct::RecSplitIndex> idx_header_hash_;
};

using StoredBlockBody = db::detail::BlockBodyForStorage;

class BodySnapshot : public Snapshot {
  public:
    explicit BodySnapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~BodySnapshot() override { close(); }

    [[nodiscard]] SnapshotPath path() const override;
    [[nodiscard]] const succinct::RecSplitIndex* idx_body_number() const { return idx_body_number_.get(); }

    using Walker = std::function<bool(BlockNum number, const StoredBlockBody* body)>;
    bool for_each_body(const Walker& walker);
    [[nodiscard]] std::optional<StoredBlockBody> next_body(uint64_t offset) const;

    std::pair<uint64_t, uint64_t> compute_txs_amount();

    [[nodiscard]] std::optional<StoredBlockBody> body_by_number(BlockNum block_height) const;

    void reopen_index() override;

  protected:
    static DecodingResult decode_body(const Snapshot::WordItem& item, StoredBlockBody& body);

    void close_index() override;

  private:
    //! Index block_num_u64 -> bodies_segment_offset
    std::unique_ptr<succinct::RecSplitIndex> idx_body_number_;
};

class TransactionSnapshot : public Snapshot {
  public:
    explicit TransactionSnapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~TransactionSnapshot() override { close(); }

    [[nodiscard]] SnapshotPath path() const override;
    [[nodiscard]] const succinct::RecSplitIndex* idx_txn_hash() const { return idx_txn_hash_.get(); }
    [[nodiscard]] const succinct::RecSplitIndex* idx_txn_hash_2_block() const { return idx_txn_hash_2_block_.get(); }

    [[nodiscard]] std::optional<Transaction> next_txn(uint64_t offset, std::optional<Hash> hash = {}) const;

    [[nodiscard]] std::optional<Transaction> txn_by_hash(const Hash& txn_hash) const;
    [[nodiscard]] std::optional<Transaction> txn_by_id(uint64_t txn_id) const;
    [[nodiscard]] std::vector<Transaction> txn_range(uint64_t base_txn_id, uint64_t txn_count, bool read_senders) const;
    [[nodiscard]] std::vector<Bytes> txn_rlp_range(uint64_t base_txn_id, uint64_t txn_count) const;

    void reopen_index() override;

  protected:
    static DecodingResult decode_txn(const Snapshot::WordItem& item, Transaction& tx);

    using Walker = std::function<bool(uint64_t i, ByteView senders_data, ByteView txn_rlp)>;
    void for_each_txn(uint64_t base_txn_id, uint64_t txn_count, const Walker& walker) const;

    void close_index() override;

  private:
    //! Index transaction_hash -> transactions_segment_offset
    std::unique_ptr<succinct::RecSplitIndex> idx_txn_hash_;

    //! Index transaction_hash -> block_number
    std::unique_ptr<succinct::RecSplitIndex> idx_txn_hash_2_block_;
};

}  // namespace silkworm::snapshot
