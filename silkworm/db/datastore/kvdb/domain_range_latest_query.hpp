// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ranges>
#include <utility>

#include <silkworm/core/common/assert.hpp>

#include "../common/pair_get.hpp"
#include "../common/ranges/caching_view.hpp"
#include "../common/ranges/lazy_view.hpp"
#include "../common/ranges/unique_view.hpp"
#include "cursor_iterator.hpp"
#include "domain.hpp"
#include "domain_codecs.hpp"
#include "mdbx.hpp"
#include "raw_codec.hpp"

namespace silkworm::datastore::kvdb {

template <
    EncoderConcept TKeyEncoder,
    DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct DomainRangeLatestQuery {
    ROTxn& tx;
    Domain entity;

    using Key = decltype(TKeyEncoder::value);
    using ResultItemKey = decltype(TKeyDecoder::value);
    using ResultItemValue = decltype(TValueDecoder::value);
    using ResultItem = std::pair<ResultItemKey, ResultItemValue>;

    static ResultItem decode_kv_pair(const std::pair<ByteView, ByteView>& kv_pair) {
        TKeyDecoder key_decoder;
        key_decoder.decode(kv_pair.first);
        ResultItemKey& key = key_decoder.value;

        TValueDecoder value_decoder;
        value_decoder.decode(kv_pair.second);
        ResultItemValue& value = value_decoder.value;

        return ResultItem{std::move(key), std::move(value)};
    }

    static constexpr auto kDecodeKVPairFunc = [](const std::pair<ByteView, ByteView>& kv_pair) -> ResultItem {
        return decode_kv_pair(kv_pair);
    };

    auto exec_with_eager_begin(Bytes key_start, Bytes key_end, bool ascending) {  // NOLINT(*-unnecessary-value-param)
        SILKWORM_ASSERT(ascending);                                               // descending is not implemented

        using CursorKVIteratorRaw = CursorKVIterator<DomainKeyDecoder<RawDecoder<ByteView>>, DomainValueDecoder<RawDecoder<ByteView>>>;
        CursorKVIteratorRaw begin_it;

        std::unique_ptr<ROCursor> cursor;
        if (entity.values_table.value_mode == mdbx::value_mode::multi) {
            cursor = tx.ro_cursor_dup_sort(entity.values_table);
        } else {
            cursor = tx.ro_cursor(entity.values_table);
        }

        auto result = cursor->lower_bound(to_slice(key_start), false);
        if (result) {
            begin_it = CursorKVIteratorRaw::make(
                std::move(cursor),
                (entity.values_table.value_mode == mdbx::value_mode::multi) ? MoveOperation::multi_nextkey_firstvalue : MoveOperation::next,
                [has_large_values = entity.has_large_values]() { return DomainKeyDecoder<RawDecoder<ByteView>>{has_large_values}; },
                [has_large_values = entity.has_large_values]() { return DomainValueDecoder<RawDecoder<ByteView>>{has_large_values}; });
        }

        auto before_key_end_predicate = [key_end = std::move(key_end)](const std::pair<ByteView, ByteView>& kv_pair) {
            return kv_pair.first < key_end;
        };

        return std::ranges::subrange{std::move(begin_it), CursorKVIteratorRaw{}} |
               std::views::transform([](auto&& kvts_pair) { return std::pair<ByteView, ByteView>{kvts_pair.first.key.value, kvts_pair.second.value.value}; }) |
               silkworm::views::unique<silkworm::views::MergeCompareFunc, PairGetFirst<ByteView, ByteView>> |  // filter out duplicate keys when has_large_values
               std::views::take_while(std::move(before_key_end_predicate)) |
               std::views::transform(kDecodeKVPairFunc) |
               silkworm::views::caching;
    }

    auto exec(const Key& key_start, const Key& key_end, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        TKeyEncoder key_start_encoder;
        key_start_encoder.value = key_start;
        Slice key_start_slice = key_start_encoder.encode();
        Bytes key_start_data = Bytes{from_slice(key_start_slice)};

        TKeyEncoder key_end_encoder;
        key_end_encoder.value = key_end;
        Slice key_end_slice = key_end_encoder.encode();
        Bytes key_end_data = Bytes{from_slice(key_end_slice)};

        auto exec_func = [query = *this, key_start = std::move(key_start_data), key_end = std::move(key_end_data), ascending]() mutable {
            return query.exec_with_eager_begin(std::move(key_start), std::move(key_end), ascending);
        };
        return silkworm::ranges::lazy(std::move(exec_func));
    }
};

}  // namespace silkworm::datastore::kvdb
