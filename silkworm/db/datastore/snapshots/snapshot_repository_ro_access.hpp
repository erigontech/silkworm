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

#include <array>
#include <map>
#include <memory>
#include <optional>
#include <ranges>
#include <utility>
#include <vector>

#include "../common/entity_name.hpp"
#include "../common/step.hpp"
#include "../common/timestamp.hpp"
#include "common/util/iterator/map_values_view.hpp"
#include "domain_cache.hpp"
#include "inverted_index_cache.hpp"
#include "segment_and_accessor_index.hpp"

namespace silkworm::snapshots {

struct SnapshotBundle;

struct SnapshotRepositoryROAccess {
    using Timestamp = datastore::Timestamp;
    using TimestampRange = datastore::TimestampRange;
    using Step = datastore::Step;
    using StepRange = datastore::StepRange;
    using Bundles = std::map<Step, std::shared_ptr<SnapshotBundle>>;

    template <class TBaseView>
    class BundlesView : public std::ranges::view_interface<BundlesView<TBaseView>> {
      public:
        BundlesView(
            TBaseView base_view,
            std::shared_ptr<Bundles> bundles)
            : base_view_(std::move(base_view)),
              bundles_(std::move(bundles)) {}

        auto begin() const { return base_view_.begin(); }
        auto end() const { return base_view_.end(); }

      private:
        TBaseView base_view_;
        std::shared_ptr<Bundles> bundles_{};
    };

    virtual ~SnapshotRepositoryROAccess() = default;

    virtual DomainGetLatestCache* domain_get_latest_cache(const datastore::EntityName& name) const = 0;
    virtual InvertedIndexSeekCache* inverted_index_seek_cache(const datastore::EntityName& name) const = 0;

    virtual size_t bundles_count() const = 0;

    //! All types of .seg and .idx files are available up to this timestamp
    virtual Timestamp max_timestamp_available() const = 0;

    virtual BundlesView<MapValuesView<Bundles::key_type, Bundles::mapped_type, Bundles>> view_bundles() const = 0;
    virtual BundlesView<MapValuesViewReverse<Bundles::key_type, Bundles::mapped_type, Bundles>> view_bundles_reverse() const = 0;

    virtual std::pair<std::optional<SegmentAndAccessorIndex>, std::shared_ptr<SnapshotBundle>> find_segment(
        const SegmentAndAccessorIndexNames& names,
        Timestamp t) const = 0;
    virtual std::shared_ptr<SnapshotBundle> find_bundle(Timestamp t) const = 0;
    virtual std::shared_ptr<SnapshotBundle> find_bundle(Step step) const = 0;

    //! Bundles fully contained within a given range: range_start <= first_start < last_end <= range_end
    virtual std::vector<std::shared_ptr<SnapshotBundle>> bundles_in_range(StepRange range) const = 0;

    //! Bundles having some steps within a given range: first_start <= range_start < range_end <= last_end
    virtual std::vector<std::shared_ptr<SnapshotBundle>> bundles_intersecting_range(StepRange range, bool ascending) const = 0;

    //! Bundles having some timestamps within a given range
    virtual std::vector<std::shared_ptr<SnapshotBundle>> bundles_intersecting_range(TimestampRange range, bool ascending) const = 0;
};

}  // namespace silkworm::snapshots
