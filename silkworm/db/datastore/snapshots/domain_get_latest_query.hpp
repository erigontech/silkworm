// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "../common/step.hpp"
#include "common/codec.hpp"
#include "common/raw_codec.hpp"
#include "domain.hpp"
#include "query_cache.hpp"
#include "query_caches.hpp"
#include "segment/kv_segment_reader.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct DomainGetLatestSegmentQuery {
    explicit DomainGetLatestSegmentQuery(Domain entity)
        : entity_{std::move(entity)} {}
    DomainGetLatestSegmentQuery(
        const SnapshotBundle& bundle,
        datastore::EntityName entity_name)
        : DomainGetLatestSegmentQuery(bundle.domain(entity_name)) {}

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
        if (!entity_.existence_index.contains(key)) {
            return std::nullopt;
        }

        return entity_.btree_index.get(key, entity_.kv_segment);
    }

  private:
    Domain entity_;
};

struct DomainGetLatestQueryRawNoCache {
    const SnapshotRepositoryROAccess& repository;
    datastore::EntityName entity_name;

    struct Result {
        Decoder::Word value;
        datastore::Step step{0};
    };

    std::optional<Result> exec(ByteView key_data) {
        for (auto& bundle_ptr : repository.view_bundles_reverse()) {
            const SnapshotBundle& bundle = *bundle_ptr;
            DomainGetLatestSegmentQuery<RawEncoder<ByteView>, RawDecoder<Decoder::Word>> query{bundle, entity_name};
            std::optional<Decoder::Word> value_data = query.exec_raw(key_data);
            if (value_data) {
                return Result{std::move(*value_data), bundle.step_range().end};
            }
        }
        return std::nullopt;
    }
};

struct DomainGetLatestQueryRawWithCache {
    using Result = DomainGetLatestQueryRawNoCache::Result;
    using CacheType = QueryCache<std::optional<Result>>;
    static inline const datastore::EntityName kName{"DomainGetLatestQueryRawWithCache"};

    DomainGetLatestQueryRawWithCache(
        const SnapshotRepositoryROAccess& repository,
        const QueryCaches& query_caches,
        datastore::EntityName entity_name)
        : query_{repository, entity_name},
          cache_{query_caches.cache<CacheType>(kName, entity_name).get()} {}

    std::optional<Result> exec(ByteView key_data) {
        if (!cache_) {
            return query_.exec(key_data);
        }

        std::optional<std::optional<Result>> cached_result;
        uint64_t cache_key{0};
        std::tie(cached_result, cache_key) = cache_->get(key_data);
        if (cached_result) {
            return std::move(*cached_result);
        }

        std::optional<Result> result = query_.exec(key_data);
        cache_->put(cache_key, result);
        return result;
    }

  private:
    DomainGetLatestQueryRawNoCache query_;
    CacheType* cache_;
};

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct DomainGetLatestQuery {
    DomainGetLatestQuery(
        const SnapshotRepositoryROAccess& repository,
        const QueryCaches& query_caches,
        datastore::EntityName entity_name)
        : query_{repository, query_caches, entity_name} {}

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);

    struct Result {
        Value value;
        datastore::Step step{0};
    };

    std::optional<Result> exec(const Key& key) {
        TKeyEncoder key_encoder;
        key_encoder.value = key;
        ByteView key_data = key_encoder.encode_word();

        auto value_data = query_.exec(key_data);
        if (!value_data) return std::nullopt;

        TValueDecoder value_decoder;
        value_decoder.decode_word(value_data->value);
        return Result{std::move(value_decoder.value), value_data->step};
    }

  private:
    DomainGetLatestQueryRawWithCache query_;
};

}  // namespace silkworm::snapshots
