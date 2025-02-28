/*
   Copyright 2025 The Silkworm Authors

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

#include <functional>
#include <ranges>
#include <variant>

#include <silkworm/core/common/assert.hpp>

#include "../common/ranges/caching_view.hpp"
#include "../common/timestamp.hpp"
#include "cursor_iterator.hpp"
#include "history.hpp"
#include "history_codecs.hpp"
#include "mdbx.hpp"
#include "raw_codec.hpp"

namespace silkworm::datastore::kvdb {

template <DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct HistoryRangeInPeriodQuery {
    ROTxn& tx;
    History entity;

    using Key = decltype(TKeyDecoder::value);
    using Value = decltype(TValueDecoder::value);
    using ResultItem = std::pair<Key, Value>;

    template <typename T>
    static constexpr bool as_bool_predicate(const T& v) {
        return !!v;
    }

    static ResultItem kv_pair_from_cursor(std::shared_ptr<ROCursor> cursor, bool has_large_values) {
        SILKWORM_ASSERT(cursor);
        CursorIterator any_it{
            std::move(cursor),
            MoveOperation::next,
            std::make_shared<HistoryKeyDecoder<TKeyDecoder>>(has_large_values),
            std::make_shared<HistoryValueDecoder<TValueDecoder>>(has_large_values),
        };
        CursorKVIterator<HistoryKeyDecoder<TKeyDecoder>, HistoryValueDecoder<TValueDecoder>> it{std::move(any_it)};

        auto kv_pair = *it;
        Key& key = kv_pair.first.key.value;
        Value& value = kv_pair.second.value.value;
        return std::pair{std::move(key), std::move(value)};
    }

    static auto kv_pair_from_cursor_func(bool has_large_values) {
        return [=](std::shared_ptr<ROCursor> cursor) -> ResultItem {
            return kv_pair_from_cursor(std::move(cursor), has_large_values);
        };
    }

    auto exec_with_eager_begin(TimestampRange ts_range, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        CursorMoveIterator begin_it;
        std::function<std::shared_ptr<ROCursor>(std::shared_ptr<ROCursor>)> seek_func;

        std::unique_ptr<ROCursor> begin_cursor;
        if (entity.values_table.value_mode == mdbx::value_mode::multi) {
            begin_cursor = tx.ro_cursor_dup_sort(entity.values_table);
        } else {
            begin_cursor = tx.ro_cursor(entity.values_table);
        }

        if (begin_cursor->to_first(false)) {
            if (entity.has_large_values) {
                begin_it = CursorMoveIterator{std::move(begin_cursor), MoveOperation::get_current};

                seek_func = [ts_range, has_large_values = entity.has_large_values, skip_current_key = std::make_shared<bool>()](std::shared_ptr<ROCursor> cursor) -> std::shared_ptr<ROCursor> {
                    auto result = cursor->current();
                    SILKWORM_ASSERT(result);

                    HistoryKeyDecoder<RawDecoder<ByteView>> key_decoder{has_large_values};
                    key_decoder.decode(result.key);

                    if (*skip_current_key) {
                        Bytes current_key{key_decoder.value.key.value};
                        do {
                            result = cursor->to_next(false);
                            if (!result) return {};
                            key_decoder.decode(result.key);
                        } while (key_decoder.value.key.value == current_key);
                    }

                    HistoryKeyEncoder<RawEncoder<ByteView>> seek_key_encoder{has_large_values};
                    seek_key_encoder.value.key.value = key_decoder.value.key.value;
                    seek_key_encoder.value.timestamp.value = ts_range.start;
                    Slice seek_key = seek_key_encoder.encode();

                    result = cursor->lower_bound(seek_key, false);
                    if (result) {
                        key_decoder.decode(result.key);
                        // if we jumped over to the next key, ts_range.start might be invalid
                        if (key_decoder.value.timestamp.value < ts_range.start) {
                            *skip_current_key = false;
                            return {};
                        } else if (key_decoder.value.timestamp.value < ts_range.end) {
                            *skip_current_key = true;
                            return cursor;
                        }
                        *skip_current_key = true;
                        return {};
                    }
                    return {};
                };
            } else {
                begin_it = CursorMoveIterator{std::move(begin_cursor), MoveOperation::multi_nextkey_firstvalue};

                seek_func = [ts_range, has_large_values = entity.has_large_values](std::shared_ptr<ROCursor> base_cursor) -> std::shared_ptr<ROCursor> {
                    auto cursor = base_cursor->clone();
                    auto result = cursor->current();
                    SILKWORM_ASSERT(result);

                    TimestampEncoder ts_range_start_encoder{ts_range.start};
                    result = dynamic_cast<ROCursorDupSort&>(*cursor).lower_bound_multivalue(result.key, ts_range_start_encoder.encode(), false);
                    if (result) {
                        HistoryValueDecoder<RawDecoder<ByteView>> value_decoder{has_large_values};
                        value_decoder.decode(result.value);
                        if (value_decoder.value.timestamp.value < ts_range.end) {
                            return std::shared_ptr<ROCursor>{std::move(cursor)};
                        }
                    }
                    return {};
                };
            }
        }

        return std::ranges::subrange{std::move(begin_it), std::default_sentinel} |
               std::views::transform(std::move(seek_func)) |
               silkworm::views::caching |
               std::views::filter(as_bool_predicate<std::shared_ptr<ROCursor>>) |
               std::views::transform(kv_pair_from_cursor_func(entity.has_large_values)) |
               silkworm::views::caching;
    }

    auto exec(TimestampRange ts_range, bool ascending) {
        auto exec_func = [query = *this, ts_range, ascending](std::monostate) mutable {
            return query.exec_with_eager_begin(ts_range, ascending);
        };
        // turn into a lazy view that runs exec_func only when iteration is started using range::begin()
        return std::views::single(std::monostate{}) | std::views::transform(std::move(exec_func)) | std::views::join;
    }
};

}  // namespace silkworm::datastore::kvdb
