// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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

    auto exec(Key key, datastore::TimestampRange ts_range, bool ascending) {
        auto timestamps_in_bundle = [entity_name = entity_name_, key = std::move(key), ts_range, ascending](const std::shared_ptr<SnapshotBundle>& bundle) {
            InvertedIndexFindByKeySegmentQuery<TKeyEncoder> query{*bundle, entity_name};
            return query.exec_filter(key, ts_range, ascending);
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
