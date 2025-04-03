// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <tl/expected.hpp>

#include "../common/timestamp.hpp"
#include "history.hpp"
#include "history_codecs.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct HistoryGetQuery {
    ROTxn& tx;
    History entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);

    enum class [[nodiscard]] NoValueReason {
        kNotFound,
        kDeleted,
    };

    tl::expected<Value, NoValueReason> exec(const Key& key, Timestamp timestamp) {
        HistoryKeyEncoder<TKeyEncoder> key_encoder{entity.has_large_values};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = timestamp;
        Slice key_slice = key_encoder.encode();

        CursorResult result{Slice{}, Slice{}, /* done = */ false};
        if (entity.has_large_values) {
            result = tx.ro_cursor(entity.values_table)->lower_bound(key_slice, false);
            if (result) {
                HistoryKeyDecoder<RawDecoder<ByteView>> key_decoder{entity.has_large_values};
                key_decoder.decode(key_slice);
                ByteView key_data = key_decoder.value.key.value;
                key_decoder.decode(result.key);
                ByteView key_data_found = key_decoder.value.key.value;
                if (key_data_found != key_data) {
                    result = CursorResult{Slice{}, Slice{}, /* done = */ false};
                }
            }
        } else {
            HistoryValueEncoder<RawEncoder<ByteView>> value_encoder{entity.has_large_values};
            value_encoder.value.timestamp.value = timestamp;
            value_encoder.value.value.value = ByteView{};
            Slice value_slice = value_encoder.encode();

            result = tx.ro_cursor_dup_sort(entity.values_table)->lower_bound_multivalue(key_slice, value_slice, false);
        }

        if (!result) return tl::unexpected{NoValueReason::kNotFound};

        HistoryValueDecoder<RawDecoder<ByteView>> empty_value_decoder{entity.has_large_values};
        empty_value_decoder.decode(result.value);
        if (empty_value_decoder.value.value.value.empty()) return tl::unexpected{NoValueReason::kDeleted};

        HistoryValueDecoder<TValueDecoder> value_decoder{entity.has_large_values};
        value_decoder.decode(result.value);
        return std::move(value_decoder.value.value.value);
    }
};

}  // namespace silkworm::datastore::kvdb
