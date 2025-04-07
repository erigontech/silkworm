// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/block_body_for_storage.hpp>
#include <silkworm/db/datastore/snapshots/common/snapshot_path.hpp>
#include <silkworm/db/datastore/snapshots/segment/seg/decompressor.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

namespace silkworm::snapshots {

class TxsAndBodiesSegmentQuery {
  public:
    class Iterator {
      public:
        Iterator(
            std::shared_ptr<seg::Decompressor> txs_decoder,
            seg::Decompressor::Iterator tx_it,
            std::shared_ptr<seg::Decompressor> bodies_decoder,
            seg::Decompressor::Iterator body_it,
            BlockNum first_block_num,
            uint64_t first_tx_id,
            uint64_t expected_tx_count,
            std::string log_title);

        // NOLINTNEXTLINE(readability-identifier-naming)
        struct value_type {
            BlockNum block_num{};
            ByteView body_rlp;
            BlockBodyForStorage body;
            ByteView tx_buffer;
        };

        using iterator_category [[maybe_unused]] = std::input_iterator_tag;
        using difference_type = std::ptrdiff_t;
        using pointer = value_type*;
        using reference = value_type&;

        reference operator*() { return value_; }
        pointer operator->() { return &value_; }

        Iterator operator++(int) { return std::exchange(*this, ++Iterator{*this}); }
        Iterator& operator++();

        friend bool operator!=(const Iterator& lhs, const Iterator& rhs) = default;
        friend bool operator==(const Iterator& lhs, const Iterator& rhs);

      private:
        void skip_bodies_until_tx_id(uint64_t tx_id);
        void decode_body_rlp(ByteView body_rlp, BlockBodyForStorage& body);

        std::shared_ptr<seg::Decompressor> txs_decoder_;
        seg::Decompressor::Iterator tx_it_;
        std::shared_ptr<seg::Decompressor> bodies_decoder_;
        seg::Decompressor::Iterator body_it_;
        uint64_t i_{};
        value_type value_;
        uint64_t first_tx_id_;
        uint64_t expected_tx_count_;
        std::string log_title_;
    };

    static_assert(std::input_or_output_iterator<Iterator>);

    TxsAndBodiesSegmentQuery(
        SnapshotPath txs_segment_path,
        std::optional<MemoryMappedRegion> txs_segment_region,
        SnapshotPath bodies_segment_path,
        std::optional<MemoryMappedRegion> bodies_segment_region,
        BlockNum first_block_num,
        uint64_t first_tx_id,
        uint64_t expected_tx_count)
        : txs_segment_path_(std::move(txs_segment_path)),
          txs_segment_region_(txs_segment_region),
          bodies_segment_path_(std::move(bodies_segment_path)),
          bodies_segment_region_(bodies_segment_region),
          first_block_num_(first_block_num),
          first_tx_id_(first_tx_id),
          expected_tx_count_(expected_tx_count) {}

    Iterator begin() const;
    Iterator end() const;

    uint64_t expected_tx_count() const { return expected_tx_count_; }

  private:
    SnapshotPath txs_segment_path_;
    std::optional<MemoryMappedRegion> txs_segment_region_;
    SnapshotPath bodies_segment_path_;
    std::optional<MemoryMappedRegion> bodies_segment_region_;
    BlockNum first_block_num_;
    uint64_t first_tx_id_;
    uint64_t expected_tx_count_;
};

}  // namespace silkworm::snapshots
