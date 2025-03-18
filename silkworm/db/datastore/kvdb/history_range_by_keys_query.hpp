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
#include "history.hpp"
#include "history_codecs.hpp"
#include "mdbx.hpp"
#include "raw_codec.hpp"

namespace silkworm::datastore::kvdb {

template <
    EncoderConcept TKeyEncoder,
    DecoderConcept TKeyDecoder, DecoderConcept TValueDecoder>
struct HistoryRangeByKeysQuery {
    ROTxn& tx;
    History entity;

    using Key = decltype(TKeyEncoder::value);
    using ResultItemKey = decltype(TKeyDecoder::value);
    using ResultItemValue = decltype(TValueDecoder::value);
    using ResultItem = std::pair<ResultItemKey, ResultItemValue>;

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
        ResultItemKey& key = kv_pair.first.key.value;
        ResultItemValue& value = kv_pair.second.value.value;
        return std::pair{std::move(key), std::move(value)};
    }

    static auto kv_pair_from_cursor_func(bool has_large_values) {
        return [=](std::shared_ptr<ROCursor> cursor) -> ResultItem {
            return kv_pair_from_cursor(std::move(cursor), has_large_values);
        };
    }

    auto exec_with_eager_begin(Bytes key_start, Bytes key_end, Timestamp timestamp, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        CursorMoveIterator begin_it;
        std::function<std::shared_ptr<ROCursor>(std::shared_ptr<ROCursor>)> seek_func;

        std::unique_ptr<ROCursor> begin_cursor;
        if (entity.values_table.value_mode == mdbx::value_mode::multi) {
            begin_cursor = tx.ro_cursor_dup_sort(entity.values_table);
        } else {
            begin_cursor = tx.ro_cursor(entity.values_table);
        }

        if (begin_cursor->lower_bound(to_slice(key_start), false)) {
            if (entity.has_large_values) {
                begin_it = CursorMoveIterator{std::move(begin_cursor), MoveOperation::get_current};

                seek_func = [timestamp, has_large_values = entity.has_large_values, skip_current_key = std::make_shared<bool>()](std::shared_ptr<ROCursor> cursor) -> std::shared_ptr<ROCursor> {
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
                    seek_key_encoder.value.timestamp.value = timestamp;
                    Slice seek_key = seek_key_encoder.encode();

                    result = cursor->lower_bound(seek_key, false);
                    if (result) {
                        key_decoder.decode(result.key);
                        // if we jumped over to the next key, timestamp might be invalid
                        if (key_decoder.value.timestamp.value < timestamp) {
                            *skip_current_key = false;
                            return {};
                        }
                        *skip_current_key = true;
                        return cursor;
                    }
                    return {};
                };
            } else {
                begin_it = CursorMoveIterator{std::move(begin_cursor), MoveOperation::multi_nextkey_firstvalue};

                seek_func = [timestamp](const std::shared_ptr<ROCursor>& base_cursor) -> std::shared_ptr<ROCursor> {
                    auto cursor = base_cursor->clone();
                    auto result = cursor->current();
                    SILKWORM_ASSERT(result);

                    TimestampEncoder ts_encoder{timestamp};
                    result = dynamic_cast<ROCursorDupSort&>(*cursor).lower_bound_multivalue(result.key, ts_encoder.encode(), false);
                    return result ? std::shared_ptr<ROCursor>{std::move(cursor)} : std::shared_ptr<ROCursor>{};
                };
            }
        }

        auto before_key_end_predicate = [key_end = std::move(key_end)](const std::shared_ptr<ROCursor>& cursor) {
            auto result = cursor->current();
            SILKWORM_ASSERT(result);
            return from_slice(result.key) < ByteView{key_end};
        };

        return std::ranges::subrange{std::move(begin_it), std::default_sentinel} |
               std::views::transform(std::move(seek_func)) |
               silkworm::views::caching |
               std::views::filter(as_bool_predicate<std::shared_ptr<ROCursor>>) |
               std::views::take_while(std::move(before_key_end_predicate)) |
               std::views::transform(kv_pair_from_cursor_func(entity.has_large_values)) |
               silkworm::views::caching;
    }

    auto exec(const Key& key_start, const Key& key_end, Timestamp timestamp, bool ascending) {
        SILKWORM_ASSERT(ascending);  // descending is not implemented

        TKeyEncoder key_start_encoder;
        key_start_encoder.value = key_start;
        Slice key_start_slice = key_start_encoder.encode();
        Bytes key_start_data = Bytes{from_slice(key_start_slice)};

        TKeyEncoder key_end_encoder;
        key_end_encoder.value = key_end;
        Slice key_end_slice = key_end_encoder.encode();
        Bytes key_end_data = Bytes{from_slice(key_end_slice)};

        auto exec_func = [query = *this, key_start = std::move(key_start_data), key_end = std::move(key_end_data), timestamp, ascending]() mutable {
            return query.exec_with_eager_begin(std::move(key_start), std::move(key_end), timestamp, ascending);
        };
        return silkworm::ranges::lazy(std::move(exec_func));
    }
};

}  // namespace silkworm::datastore::kvdb
