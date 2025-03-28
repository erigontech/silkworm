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
#include "domain_cache.hpp"
#include "segment/kv_segment_reader.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct DomainGetLatestSegmentQuery {
    explicit DomainGetLatestSegmentQuery(Domain entity, DomainCache* cache)
        : entity_{std::move(entity)}, cache_{cache} {}
    DomainGetLatestSegmentQuery(
        const SnapshotBundle& bundle,
        datastore::EntityName entity_name,
        DomainCache* cache)
        : DomainGetLatestSegmentQuery(bundle.domain(entity_name), cache) {}

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);
    using Word = typename TValueDecoder::Word;

    std::optional<Value> exec(const Key& key) {
        TKeyEncoder key_encoder;
        key_encoder.value = key;
        ByteView key_data = key_encoder.encode_word();

        std::optional<Word> value_data = exec_raw(key_data);
        if (!value_data) {
            return std::nullopt;
        }

        TValueDecoder value_decoder;
        value_decoder.decode_word(*value_data);
        return std::move(value_decoder.value);
    }

    std::optional<Word> exec_raw(const ByteView key) {
        std::optional<Word> value_data;
        uint64_t key_hash_hi{0};

        if (cache_) {
            if (std::tie(value_data, key_hash_hi) = cache_->get(key); value_data) {
                return value_data;
            }
        }

        if (!entity_.existence_index.contains(key)) {
            return std::nullopt;
        }

        value_data = entity_.btree_index.get(key, entity_.kv_segment);
        if (cache_ && value_data) {
            cache_->put(key_hash_hi, *value_data);
        }

        return value_data;
    }

  private:
    Domain entity_;
    DomainCache* cache_;
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
        DomainCache* cache = repository.domain_cache(entity_name);

        TKeyEncoder key_encoder;
        key_encoder.value = key;
        ByteView key_data = key_encoder.encode_word();

        for (auto& bundle_ptr : repository.view_bundles_reverse()) {
            const SnapshotBundle& bundle = *bundle_ptr;
            DomainGetLatestSegmentQuery<TKeyEncoder, TValueDecoder> query{bundle, entity_name, cache};
            auto value = query.exec_raw(key_data);
            if (value) {
                TValueDecoder value_decoder;
                value_decoder.decode_word(*value);
                return Result{std::move(value_decoder.value), bundle.step_range().end};
            }
        }
        return std::nullopt;
    }
};

}  // namespace silkworm::snapshots
