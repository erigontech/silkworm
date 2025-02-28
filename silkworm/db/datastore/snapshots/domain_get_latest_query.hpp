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

#include "../common/step.hpp"
#include "common/codec.hpp"
#include "common/raw_codec.hpp"
#include "domain.hpp"
#include "segment/kv_segment_reader.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct DomainGetLatestSegmentQuery {
    explicit DomainGetLatestSegmentQuery(Domain entity)
        : entity_{std::move(entity)} {}
    explicit DomainGetLatestSegmentQuery(
        const SnapshotBundle& bundle,
        datastore::EntityName entity_name)
        : entity_{bundle.domain(entity_name)} {}

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);

    std::optional<Value> exec(const Key& key) {
        TKeyEncoder key_encoder;
        key_encoder.value = key;
        ByteView key_data = key_encoder.encode_word();

        if (!entity_.existence_index.contains(key_data)) {
            return std::nullopt;
        }

        std::optional<Bytes> value_data = entity_.btree_index.get(key_data, entity_.kv_segment);
        if (!value_data) {
            return std::nullopt;
        }

        TValueDecoder value_decoder;
        BytesOrByteView value{std::move(*value_data)};
        value_decoder.decode_word(value);
        return std::move(value_decoder.value);
    }

  private:
    Domain entity_;
};

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct DomainGetLatestQuery {
    const SnapshotRepositoryROAccess& repository;
    datastore::EntityName entity_name;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);

    struct Result {
        Value value;
        datastore::Step step{0};
    };

    std::optional<Result> exec(const Key& key) {
        for (auto& bundle_ptr : repository.view_bundles_reverse()) {
            const SnapshotBundle& bundle = *bundle_ptr;
            DomainGetLatestSegmentQuery<TKeyEncoder, TValueDecoder> query{bundle, entity_name};
            auto value = query.exec(key);
            if (value) {
                return Result{std::move(*value), bundle.step_range().end};
            }
        }
        return std::nullopt;
    }
};

}  // namespace silkworm::snapshots
