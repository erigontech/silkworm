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

#include <iterator>
#include <ranges>
#include <utility>
#include <vector>

#include <silkworm/core/common/assert.hpp>

#include "../common/entity_name.hpp"
#include "../common/pair_get.hpp"
#include "../common/ranges/caching_view.hpp"
#include "../common/ranges/lazy_view.hpp"
#include "../common/ranges/merge_many_view.hpp"
#include "../common/ranges/owning_view.hpp"
#include "common/codec.hpp"
#include "domain.hpp"
#include "snapshot_bundle.hpp"
#include "snapshot_repository_ro_access.hpp"

namespace silkworm::snapshots {

struct DomainRangeLatestSegmentQuery {
    explicit DomainRangeLatestSegmentQuery(Domain entity)
        : entity_{std::move(entity)} {}
    explicit DomainRangeLatestSegmentQuery(
        const SnapshotBundle& bundle,
        datastore::EntityName entity_name)
        : entity_{bundle.domain(entity_name)} {}

    using ResultItem = btree::BTreeIndex::Cursor::value_type;

    auto exec_with_eager_begin(Bytes key_start, Bytes key_end, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        auto begin_it = entity_.btree_index.seek(key_start, entity_.kv_segment).value_or(btree::BTreeIndex::Cursor{});

        return std::ranges::subrange{std::move(begin_it), std::default_sentinel} |
               std::views::take_while([key_end = std::move(key_end)](const auto& kv_pair) { return ByteView{kv_pair.first} < key_end; });
    }

    auto exec(Bytes key_start, Bytes key_end, bool ascending) {
        auto exec_func = [query = *this, key_start = std::move(key_start), key_end = std::move(key_end), ascending]() mutable {
            return query.exec_with_eager_begin(std::move(key_start), std::move(key_end), ascending);
        };
        return silkworm::ranges::lazy(std::move(exec_func));
    }

  private:
    Domain entity_;
};

template <
    EncoderConcept TKeyEncoder,
    DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct DomainRangeLatestQuery {
    const SnapshotRepositoryROAccess& repository;
    datastore::EntityName entity_name;

    using Key = decltype(TKeyEncoder::value);
    using ResultItemKey = decltype(TKeyDecoder::value);
    using ResultItemValue = decltype(TValueDecoder::value);
    using ResultItem = std::pair<ResultItemKey, ResultItemValue>;
    using Word = Decoder::Word;

    static ResultItem decode_kv_pair(std::pair<Word, Word>&& kv_pair) {
        if constexpr (std::same_as<ResultItem, std::pair<Word, Word>>) {
            return std::move(kv_pair);
        }

        TKeyDecoder key_decoder;
        key_decoder.decode_word(kv_pair.first);
        ResultItemKey& key = key_decoder.value;

        TValueDecoder value_decoder;
        value_decoder.decode_word(kv_pair.second);
        ResultItemValue& value = value_decoder.value;

        return ResultItem{std::move(key), std::move(value)};
    }

    static constexpr auto kDecodeKVPairFunc = [](std::pair<Word, Word>& kv_pair) -> ResultItem {
        return decode_kv_pair(std::move(kv_pair));
    };

    auto exec(const Key& key_start, const Key& key_end, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        TKeyEncoder key_start_encoder;
        key_start_encoder.value = key_start;
        ByteView key_start_data = key_start_encoder.encode_word();

        TKeyEncoder key_end_encoder;
        key_end_encoder.value = key_end;
        ByteView key_end_data = key_end_encoder.encode_word();

        auto results_in_bundle = [entity_name1 = this->entity_name, key_start_data = Bytes{key_start_data}, key_end_data = Bytes{key_end_data}, ascending](const std::shared_ptr<SnapshotBundle>& bundle_ptr) {
            const SnapshotBundle& bundle = *bundle_ptr;
            DomainRangeLatestSegmentQuery query{bundle, entity_name1};
            return query.exec(key_start_data, key_end_data, ascending);
        };

        auto bundle_results = silkworm::ranges::owning_view(repository.view_bundles_reverse()) |
                              std::views::transform(std::move(results_in_bundle));

        auto results = silkworm::views::merge_unique_many(
            std::move(bundle_results),
            silkworm::views::MergeCompareFunc{},
            PairGetFirst<DomainRangeLatestSegmentQuery::ResultItem::first_type, DomainRangeLatestSegmentQuery::ResultItem::second_type>{});

        return silkworm::ranges::owning_view(std::move(results)) |
               std::views::transform(kDecodeKVPairFunc) |
               silkworm::views::caching;
    }
};

}  // namespace silkworm::snapshots
