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
