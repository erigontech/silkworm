/*
   Copyright 2024 The Silkworm Authors

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

#include <cstdint>
#include <memory>
#include <optional>

#include <silkworm/db/datastore/etl/collector.hpp>
#include <silkworm/db/datastore/snapshots/common/snapshot_path.hpp>
#include <silkworm/db/datastore/snapshots/index_builder.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

#include "../schema_config.hpp"
#include "../step_block_num_converter.hpp"
#include "txn_index.hpp"
#include "txs_and_bodies_query.hpp"

namespace silkworm::snapshots {

class TransactionToBlockIndexInputDataQuery : public IndexInputDataQuery {
  public:
    explicit TransactionToBlockIndexInputDataQuery(TxsAndBodiesSegmentQuery query)
        : query_(std::move(query)) {}

    Iterator begin() override;
    Iterator end() override;
    size_t keys_count() override;
    std::pair<std::shared_ptr<void>, Iterator::value_type> next_iterator(std::shared_ptr<void> it_impl) override;
    bool equal_iterators(std::shared_ptr<void> lhs_it_impl, std::shared_ptr<void> rhs_it_impl) const override;

  private:
    TxsAndBodiesSegmentQuery query_;
};

class TransactionToBlockIndex {
  public:
    static IndexBuilder make(
        SnapshotPath bodies_segment_path,
        SnapshotPath segment_path) {
        auto step_converter = db::blocks::kStepToBlockNumConverter;
        BlockNum first_block_num = step_converter.timestamp_from_step(segment_path.step_range().start);
        return make(
            std::move(bodies_segment_path),
            std::nullopt,
            std::move(segment_path),
            std::nullopt,
            first_block_num);
    }

    static IndexBuilder make(
        SnapshotPath bodies_segment_path,
        SnapshotPath segment_path,
        BlockNum first_block_num) {
        return make(
            std::move(bodies_segment_path),
            std::nullopt,
            std::move(segment_path),
            std::nullopt,
            first_block_num);
    }

    static IndexBuilder make(
        SnapshotPath bodies_segment_path,
        std::optional<MemoryMappedRegion> bodies_segment_region,
        SnapshotPath segment_path,
        std::optional<MemoryMappedRegion> segment_region) {
        auto step_converter = db::blocks::kStepToBlockNumConverter;
        BlockNum first_block_num = step_converter.timestamp_from_step(segment_path.step_range().start);
        return make(
            std::move(bodies_segment_path),
            bodies_segment_region,
            std::move(segment_path),
            segment_region,
            first_block_num);
    }

    static IndexBuilder make(
        SnapshotPath bodies_segment_path,
        std::optional<MemoryMappedRegion> bodies_segment_region,
        SnapshotPath segment_path,
        std::optional<MemoryMappedRegion> segment_region,
        BlockNum first_block_num);

  private:
    static IndexDescriptor make_descriptor(const SnapshotPath& segment_path, BlockNum first_block_num, uint64_t first_tx_id) {
        return {
            .index_file = segment_path.related_path(std::string{db::blocks::kIdxTxnHash2BlockTag}, db::blocks::kIdxExtension),
            .key_factory = std::make_unique<TransactionKeyFactory>(first_tx_id),
            .base_data_id = first_block_num,
            .double_enum_index = false,
            .etl_buffer_size = datastore::etl::kOptimalBufferSize / 2,
        };
    }
};

}  // namespace silkworm::snapshots
