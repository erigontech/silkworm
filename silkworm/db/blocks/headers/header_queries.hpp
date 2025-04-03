// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/snapshots/basic_queries.hpp>

#include "../schema_config.hpp"
#include "header_segment.hpp"

namespace silkworm::snapshots {

using HeaderFindByBlockNumSegmentQuery = FindByIdSegmentQuery<HeaderSegmentWordDecoder, db::blocks::kHeaderSegmentAndIdxNames>;

struct HeaderFindByBlockNumQuery : public FindByTimestampMapQuery<HeaderFindByBlockNumSegmentQuery> {
    using FindByTimestampMapQuery::FindByTimestampMapQuery;
    std::optional<BlockHeader> exec(BlockNum block_num) {
        return FindByTimestampMapQuery::exec(block_num, block_num);
    }
};

using HeaderFindByHashSegmentQuery = FindByHashSegmentQuery<HeaderSegmentWordDecoder, db::blocks::kHeaderSegmentAndIdxNames>;
using HeaderFindByHashQuery = FindMapQuery<HeaderFindByHashSegmentQuery>;

}  // namespace silkworm::snapshots
