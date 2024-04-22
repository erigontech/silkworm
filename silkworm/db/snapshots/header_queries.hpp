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

#include "basic_queries.hpp"
#include "header_snapshot.hpp"

namespace silkworm::snapshots {

struct HeaderFindByBlockNumQuery : public FindByIdQuery<HeaderSnapshotReader> {
    using FindByIdQuery<HeaderSnapshotReader>::FindByIdQuery;

    std::optional<BlockHeader> exec(BlockNum id) {
        // TODO: move this check inside ordinal_lookup_by_data_id if possible and remove this method
        if ((id < reader_.block_from()) || (id >= reader_.block_to())) return std::nullopt;
        return FindByIdQuery<HeaderSnapshotReader>::exec(id);
    }
};

using HeaderFindByHashQuery = FindByHashQuery<HeaderSnapshotReader>;

}  // namespace silkworm::snapshots
