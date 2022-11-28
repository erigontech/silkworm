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
#include <string>
#include <utility>

#include <silkworm/common/base.hpp>
#include <silkworm/db/util.hpp>
#include <silkworm/snapshot/decompressor.hpp>
#include <silkworm/types/block.hpp>

namespace silkworm {

class Snapshot {
  public:
    static constexpr uint64_t kPageSize{4096};

    explicit Snapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to);
    virtual ~Snapshot() = default;

    [[nodiscard]] std::filesystem::path path() const { return path_; }

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

    void close();

  protected:
    void close_segment();
    virtual void close_index() = 0;

    std::filesystem::path path_;
    BlockNum block_from_{0};
    BlockNum block_to_{0};
    Decompressor decoder_;
};

class HeaderSnapshot : public Snapshot {
  public:
    explicit HeaderSnapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~HeaderSnapshot() override { close(); }

    using Walker = std::function<bool(const BlockHeader* header)>;
    bool for_each_header(const Walker& walker);

    void reopen_index() override;

  protected:
    void close_index() override;

  private:
    //! Index header_hash -> headers_segment_offset
    // uint64_t* idx_header_hash_{nullptr}; // TODO(canepat) recsplit.Index
};

class BodySnapshot : public Snapshot {
  public:
    explicit BodySnapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~BodySnapshot() override { close(); }

    using Walker = std::function<bool(BlockNum number, const db::detail::BlockBodyForStorage* body)>;
    bool for_each_body(const Walker& walker);

    void reopen_index() override;

  protected:
    void close_index() override;

  private:
    //! Index block_num_u64 -> bodies_segment_offset
    // uint64_t* idx_body_number_{nullptr}; // TODO(canepat) recsplit.Index
};

class TransactionSnapshot : public Snapshot {
  public:
    explicit TransactionSnapshot(std::filesystem::path path, BlockNum block_from, BlockNum block_to)
        : Snapshot(std::move(path), block_from, block_to) {}
    ~TransactionSnapshot() override { close(); }

    void reopen_index() override;

  protected:
    void close_index() override;

  private:
    //! Index transaction_hash -> transactions_segment_offset
    // uint64_t* idx_txn_hash_{nullptr}; // TODO(canepat) recsplit.Index

    //! Index transaction_hash -> block_number
    // uint64_t* idx_txn_hash_2_block_{nullptr}; // TODO(canepat) recsplit.Index
};

}  // namespace silkworm
