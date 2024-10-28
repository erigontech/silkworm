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

#include <silkworm/db/datastore/snapshots/basic_queries.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository.hpp>

#include "body_segment.hpp"

namespace silkworm::snapshots {

using BodyFindByBlockNumQuery = FindByIdQuery<BodySegmentReader>;

class BodyFindByBlockNumMultiQuery {
  public:
    // TODO: use a sub-interface of SnapshotRepository
    explicit BodyFindByBlockNumMultiQuery(SnapshotRepository& repository)
        : repository_{repository} {}

    std::optional<BlockBodyForStorage> exec(BlockNum block_num) {
        const auto [segment_and_index, _] = repository_.find_segment(SnapshotType::bodies, block_num);
        if (!segment_and_index) return std::nullopt;
        return BodyFindByBlockNumQuery{*segment_and_index}.exec(block_num);
    }

  private:
    SnapshotRepository& repository_;
};

}  // namespace silkworm::snapshots
