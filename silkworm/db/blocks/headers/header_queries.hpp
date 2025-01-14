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

#include "../schema_config.hpp"
#include "header_segment.hpp"

namespace silkworm::snapshots {

using HeaderFindByBlockNumSegmentQuery = FindByIdSegmentQuery<HeaderSegmentReader, &db::blocks::kHeaderSegmentAndIdxNames>;

struct HeaderFindByBlockNumQuery : public FindByTimestampMapQuery<HeaderFindByBlockNumSegmentQuery> {
    using FindByTimestampMapQuery::FindByTimestampMapQuery;
    std::optional<BlockHeader> exec(BlockNum block_num) {
        return FindByTimestampMapQuery::exec(block_num, block_num);
    }
};

using HeaderFindByHashSegmentQuery = FindByHashSegmentQuery<HeaderSegmentReader, &db::blocks::kHeaderSegmentAndIdxNames>;
using HeaderFindByHashQuery = FindMapQuery<HeaderFindByHashSegmentQuery>;

}  // namespace silkworm::snapshots
