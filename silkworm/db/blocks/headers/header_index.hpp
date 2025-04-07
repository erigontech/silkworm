// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <memory>
#include <optional>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/db/datastore/snapshots/common/snapshot_path.hpp>
#include <silkworm/db/datastore/snapshots/index_builder.hpp>
#include <silkworm/infra/common/memory_mapped_file.hpp>

#include "../schema_config.hpp"
#include "../step_block_num_converter.hpp"

namespace silkworm::snapshots {

class HeaderIndex {
  public:
    static IndexBuilder make(SnapshotPath segment_path, std::optional<MemoryMappedRegion> segment_region = std::nullopt) {
        auto descriptor = make_descriptor(segment_path);
        auto query = std::make_unique<DecompressorIndexInputDataQuery>(std::move(segment_path), segment_region);
        return IndexBuilder{std::move(descriptor), std::move(query)};
    }

    struct KeyFactory : IndexKeyFactory {
        ~KeyFactory() override = default;
        Bytes make(ByteView key_data, uint64_t i) override;
    };

  private:
    static IndexDescriptor make_descriptor(const SnapshotPath& segment_path) {
        auto step_converter = db::blocks::kStepToBlockNumConverter;
        return {
            .index_file = segment_path.related_path_ext(db::blocks::kIdxExtension),
            .key_factory = std::make_unique<KeyFactory>(),
            .base_data_id = step_converter.timestamp_from_step(segment_path.step_range().start),
        };
    }
};

}  // namespace silkworm::snapshots
