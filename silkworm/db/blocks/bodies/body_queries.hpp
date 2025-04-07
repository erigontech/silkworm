// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/db/datastore/snapshots/basic_queries.hpp>
#include <silkworm/db/datastore/snapshots/snapshot_repository_ro_access.hpp>

#include "../schema_config.hpp"
#include "body_segment.hpp"

namespace silkworm::snapshots {

using BodyFindByBlockNumSegmentQuery = FindByIdSegmentQuery<BodySegmentWordDecoder, db::blocks::kBodySegmentAndIdxNames>;
using RawBodyFindByBlockNumSegmentQuery = FindByIdSegmentQuery<RawDecoder<Bytes>, db::blocks::kBodySegmentAndIdxNames>;

struct BodyFindByBlockNumQuery : public FindByTimestampMapQuery<BodyFindByBlockNumSegmentQuery> {
    using FindByTimestampMapQuery::FindByTimestampMapQuery;
    std::optional<BlockBodyForStorage> exec(BlockNum block_num) {
        return FindByTimestampMapQuery::exec(block_num, block_num);
    }
};

struct RawBodyFindByBlockNumQuery : public FindByTimestampMapQuery<RawBodyFindByBlockNumSegmentQuery> {
    using FindByTimestampMapQuery::FindByTimestampMapQuery;
    std::optional<Bytes> exec(BlockNum block_num) {
        return FindByTimestampMapQuery::exec(block_num, block_num);
    }
};

}  // namespace silkworm::snapshots
