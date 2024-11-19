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

#include <silkworm/core/types/hash.hpp>

#include "segment/segment_reader.hpp"
#include "segment_and_index.hpp"

namespace silkworm::snapshots {

template <segment::SegmentReaderConcept TSegmentReader>
class BasicQuery {
  public:
    explicit BasicQuery(
        const SegmentAndIndex segment_and_index)
        : reader_{segment_and_index.segment},
          index_{segment_and_index.index} {}

  protected:
    TSegmentReader reader_;
    const Index& index_;
};

template <segment::SegmentReaderConcept TSegmentReader>
struct FindByIdQuery : public BasicQuery<TSegmentReader> {
    using BasicQuery<TSegmentReader>::BasicQuery;

    std::optional<typename TSegmentReader::Iterator::value_type> exec(uint64_t id) {
        auto offset = this->index_.lookup_by_data_id(id);
        if (!offset) {
            return std::nullopt;
        }

        return this->reader_.seek_one(*offset);
    }
};

template <segment::SegmentReaderConcept TSegmentReader>
struct FindByHashQuery : public BasicQuery<TSegmentReader> {
    using BasicQuery<TSegmentReader>::BasicQuery;

    std::optional<typename TSegmentReader::Iterator::value_type> exec(const Hash& hash) {
        auto offset = this->index_.lookup_by_hash(hash);
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

template <segment::SegmentReaderConcept TSegmentReader>
struct RangeFromIdQuery : public BasicQuery<TSegmentReader> {
    using BasicQuery<TSegmentReader>::BasicQuery;

    std::vector<typename TSegmentReader::Iterator::value_type> exec_into_vector(uint64_t first_id, uint64_t count) {
        auto offset = this->index_.lookup_by_data_id(first_id);
        if (!offset) {
            return {};
        }

        return this->reader_.read_into_vector(*offset, count);
    }
};

}  // namespace silkworm::snapshots
