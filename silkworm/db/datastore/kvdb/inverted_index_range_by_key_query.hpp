// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ranges>
#include <utility>

#include "../common/ranges/lazy_view.hpp"
#include "../common/timestamp.hpp"
#include "codec.hpp"
#include "cursor_iterator.hpp"
#include "inverted_index.hpp"
#include "mdbx.hpp"
#include "timestamp_codec.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder>
struct InvertedIndexRangeByKeyQuery {
    ROTxn& tx;
    InvertedIndex entity;

    using Key = decltype(TKeyEncoder::value);

    //! A range of timestamps
    using Timestamps = std::ranges::filter_view<
        std::ranges::subrange<CursorValuesIterator<TimestampDecoder>>,
        decltype(std::declval<TimestampRange>().contains_predicate())>;

    CursorValuesIterator<TimestampDecoder> begin(Key key, TimestampRange ts_range, bool ascending) {
        auto cursor = tx.ro_cursor_dup_sort(entity.index_table);

        TKeyEncoder key_encoder;
        key_encoder.value = std::move(key);
        Slice key_data = key_encoder.encode();

        TimestampEncoder ts_encoder;
        ts_encoder.value = ascending ? ts_range.start : ts_range.end;
        Slice ts_data = ts_encoder.encode();

        CursorResult result = cursor->lower_bound_multivalue(key_data, ts_data, false);

        if (!ascending) {
            if (result) {
                result = cursor->to_current_prev_multi(false);
            } else {
                result = cursor->find(key_data, false);
                if (result) {
                    cursor->to_current_last_multi(false);
                }
            }
        }

        if (result) {
            MoveOperation move_op = ascending ? MoveOperation::multi_currentkey_nextvalue : MoveOperation::multi_currentkey_prevvalue;
            auto it = CursorValuesIterator<TimestampDecoder>::make(std::move(cursor), move_op);
            if (ts_range.contains(*it)) {
                return it;
            }
        }

        return {};
    }

    Timestamps exec_with_eager_begin(Key key, TimestampRange ts_range, bool ascending) {
        auto begin_it = begin(std::move(key), ts_range, ascending);
        return std::ranges::subrange{std::move(begin_it), CursorValuesIterator<TimestampDecoder>{}} |
               std::views::filter(ts_range.contains_predicate());
    }

    auto exec(Key key, TimestampRange ts_range, bool ascending) {
        auto exec_func = [query = *this, key = std::move(key), ts_range, ascending]() mutable {
            return query.exec_with_eager_begin(std::move(key), ts_range, ascending);
        };
        return silkworm::ranges::lazy(std::move(exec_func));
    }
};

}  // namespace silkworm::datastore::kvdb
