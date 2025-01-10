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
#include <optional>
#include <utility>

#include <silkworm/core/types/hash.hpp>

#include "segment/segment_reader.hpp"
#include "segment_and_accessor_index.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <
    segment::SegmentReaderConcept TSegmentReader,
    const SegmentAndAccessorIndexNames* segment_names>
class BasicSegmentQuery {
  public:
    explicit BasicSegmentQuery(
        const SegmentAndAccessorIndex segment_and_index)
        : reader_{segment_and_index.segment},
          index_{segment_and_index.index} {}

    explicit BasicSegmentQuery(const SegmentAndAccessorIndexProvider& bundle)
        : BasicSegmentQuery{bundle.segment_and_accessor_index(*segment_names)} {}

  protected:
    TSegmentReader reader_;
    const rec_split::AccessorIndex& index_;
};

template <
    segment::SegmentReaderConcept TSegmentReader,
    const SegmentAndAccessorIndexNames* segment_names>
struct FindByIdSegmentQuery : public BasicSegmentQuery<TSegmentReader, segment_names> {
    using BasicSegmentQuery<TSegmentReader, segment_names>::BasicSegmentQuery;

    std::optional<typename TSegmentReader::Iterator::value_type> exec(uint64_t id) {
        auto offset = this->index_.lookup_by_data_id(id);
        if (!offset) {
            return std::nullopt;
        }

        return this->reader_.seek_one(*offset);
    }
};

template <
    segment::SegmentReaderConcept TSegmentReader,
    const SegmentAndAccessorIndexNames* segment_names>
struct FindByHashSegmentQuery : public BasicSegmentQuery<TSegmentReader, segment_names> {
    using BasicSegmentQuery<TSegmentReader, segment_names>::BasicSegmentQuery;

    std::optional<typename TSegmentReader::Iterator::value_type> exec(const Hash& hash) {
        auto offset = this->index_.lookup_by_key(hash);
        if (!offset) {
            return std::nullopt;
        }

        auto result = this->reader_.seek_one(*offset, hash);

        // We *must* ensure that the retrieved txn hash matches because there is no way to know if key exists in MPHF
        if (result && (result->hash() != hash)) {
            return std::nullopt;
        }

        return result;
    }
};

template <
    segment::SegmentReaderConcept TSegmentReader,
    const SegmentAndAccessorIndexNames* segment_names>
struct RangeFromIdSegmentQuery : public BasicSegmentQuery<TSegmentReader, segment_names> {
    using BasicSegmentQuery<TSegmentReader, segment_names>::BasicSegmentQuery;

    std::optional<std::vector<typename TSegmentReader::Iterator::value_type>> exec(uint64_t first_id, uint64_t count) {
        auto offset = this->index_.lookup_by_data_id(first_id);
        if (!offset) {
            return std::nullopt;
        }

        return this->reader_.read_into_vector(*offset, count);
    }
};

//! Given a TSegmentQuery that returns an optional value, runs it for all bundles and returns the last non-null result.
//! Iterating backwards by default is an optimization assuming that results are often found in the most recent snapshots.
template <class TSegmentQuery>
struct FindMapQuery {
    explicit FindMapQuery(const SnapshotRepositoryROAccess& repository)
        : repository_{repository} {}

    auto exec(auto&&... args) {
        for (const auto& bundle_ptr : repository_.view_bundles_reverse()) {
            TSegmentQuery query{*bundle_ptr};
            auto result = query.exec(args...);
            if (result) {
                return result;
            }
        }
        // std::nullopt<ResultType>
        return decltype(std::declval<TSegmentQuery>().exec(args...)){};
    }

  protected:
    const SnapshotRepositoryROAccess& repository_;
};

//! Given a timestamp and a TSegmentQuery, runs it for a bundle located by that timestamp.
template <class TSegmentQuery>
struct FindByTimestampMapQuery {
    explicit FindByTimestampMapQuery(const SnapshotRepositoryROAccess& repository)
        : repository_{repository} {}

    auto exec(SnapshotRepositoryROAccess::Timestamp t, auto&&... args) {
        auto bundle_ptr = repository_.find_bundle(t);
        if (bundle_ptr) {
            TSegmentQuery query{*bundle_ptr};
            return query.exec(args...);
        }
        // std::nullopt<ResultType>
        return decltype(std::declval<TSegmentQuery>().exec(args...)){};
    }

  protected:
    const SnapshotRepositoryROAccess& repository_;
};

}  // namespace silkworm::snapshots
