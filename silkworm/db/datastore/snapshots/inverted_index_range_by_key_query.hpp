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

#include <ranges>

#include "../common/entity_name.hpp"
#include "../common/ranges/owning_view.hpp"
#include "../common/timestamp.hpp"
#include "inverted_index_find_by_key_segment_query.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <EncoderConcept TKeyEncoder>
struct InvertedIndexRangeByKeyQuery {
    explicit InvertedIndexRangeByKeyQuery(
        const SnapshotRepositoryROAccess& repository,
        datastore::EntityName entity_name)
        : repository_{repository},
          entity_name_{std::move(entity_name)} {}

    using Key = decltype(TKeyEncoder::value);

    template <bool ascending = true>
    auto exec(Key key, datastore::TimestampRange ts_range) {
        auto timestamps_in_bundle = [entity_name = entity_name_, key = std::move(key), ts_range](const std::shared_ptr<SnapshotBundle>& bundle) {
            InvertedIndexFindByKeySegmentQuery<TKeyEncoder> query{*bundle, entity_name};
            return query.template exec_filter<ascending>(key, ts_range);
        };

        return silkworm::ranges::owning_view(repository_.bundles_intersecting_range(ts_range, ascending)) |
               std::views::transform(std::move(timestamps_in_bundle)) |
               std::views::join;
    }

  private:
    const SnapshotRepositoryROAccess& repository_;
    datastore::EntityName entity_name_;
};

}  // namespace silkworm::snapshots
