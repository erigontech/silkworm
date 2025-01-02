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

#include <optional>

#include "../common/step.hpp"
#include "big_endian_codec.hpp"
#include "codec.hpp"
#include "history.hpp"
#include "kvts_codec.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

struct Domain {
    const MapConfig& values_table;
    bool has_large_values;
    std::optional<History> history;
};

struct InvertedStepCodec : public Codec {
    Step value{0};
    BigEndianU64Codec codec;
    static constexpr size_t kEncodedSize = sizeof(decltype(BigEndianU64Codec::value));

    ~InvertedStepCodec() override = default;

    Slice encode() override {
        codec.value = ~value.value;
        return codec.encode();
    }

    void decode(Slice slice) override {
        codec.decode(slice);
        value = Step(~codec.value);
    }
};

static_assert(EncoderConcept<InvertedStepCodec>);
static_assert(DecoderConcept<InvertedStepCodec>);

template <EncoderConcept TEncoder>
using DomainKeyEncoder = KVTSKeyEncoder<TEncoder, InvertedStepCodec>;

template <EncoderConcept TEncoder>
using DomainValueEncoder = KVTSValueEncoder<TEncoder, InvertedStepCodec>;

template <DecoderConcept TDecoder>
using DomainKeyDecoder = KVTSKeyDecoder<TDecoder, InvertedStepCodec, InvertedStepCodec::kEncodedSize>;

template <DecoderConcept TDecoder>
using DomainValueDecoder = KVTSValueDecoder<TDecoder, InvertedStepCodec, InvertedStepCodec::kEncodedSize>;

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainPutLatestQuery {
    RWTxn& tx;
    Domain entity;

    using TKey = decltype(TKeyEncoder::value);
    using TValue = decltype(TValueEncoder::value);

    void exec(const TKey& key, const TValue& value, Step step) {
        DomainKeyEncoder<TKeyEncoder> key_encoder{entity.has_large_values};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = step;

        DomainValueEncoder<TValueEncoder> value_encoder{entity.has_large_values};
        value_encoder.value.value.value = value;
        value_encoder.value.timestamp.value = step;

        tx.rw_cursor(entity.values_table)->insert(key_encoder.encode(), value_encoder.encode());
    }
};

template <EncoderConcept TKeyEncoder, DecoderConcept TValueDecoder>
struct DomainGetLatestQuery {
    RWTxn& tx;
    Domain entity;

    using TKey = decltype(TKeyEncoder::value);
    using TValue = decltype(TValueDecoder::value);

    struct Result {
        TValue value;
        Step step;
    };

    std::optional<Result> exec(const TKey& key) {
        DomainKeyEncoder<TKeyEncoder> key_encoder{/* has_large_values = */ false};
        key_encoder.value.key.value = key;
        Slice key_slice = key_encoder.encode();

        auto result = tx.ro_cursor(entity.values_table)->lower_bound(key_slice, false);
        if (!result) return std::nullopt;

        DomainKeyDecoder<RawDecoder<ByteView>> key_decoder{entity.has_large_values};
        key_decoder.decode(result.key);
        if (key_decoder.value.key.value != from_slice(key_slice)) return std::nullopt;

        DomainValueDecoder<RawDecoder<ByteView>> empty_value_decoder{entity.has_large_values};
        empty_value_decoder.decode(result.value);
        if (empty_value_decoder.value.value.value.empty()) return std::nullopt;

        DomainValueDecoder<TValueDecoder> value_decoder{entity.has_large_values};
        value_decoder.decode(result.value);

        Step step = Step(key_decoder.value.timestamp.value.value | value_decoder.value.timestamp.value.value);

        return Result{std::move(value_decoder.value.value.value), step};
    }
};

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainPutQuery {
    RWTxn& tx;
    Domain entity;

    using TKey = decltype(TKeyEncoder::value);
    using TValue = decltype(TValueEncoder::value);

    void exec(
        const TKey& key,
        const TValue& value,
        Timestamp timestamp,
        const std::optional<TValue>& prev_value,
        Step prev_step) {
        DomainPutLatestQuery<TKeyEncoder, TValueEncoder> value_query{tx, entity};
        value_query.exec(key, value, prev_step);

        if (entity.history) {
            if (prev_value) {
                HistoryPutQuery<TKeyEncoder, TValueEncoder> history_query{tx, *entity.history};
                history_query.exec(key, *prev_value, timestamp);
            } else {
                HistoryDeleteQuery<TKeyEncoder> history_query{tx, *entity.history};
                history_query.exec(key, timestamp);
            }
        }
    }
};

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainDeleteQuery {
    RWTxn& tx;
    Domain entity;

    using TKey = decltype(TKeyEncoder::value);
    using TValue = decltype(TValueEncoder::value);

    void exec(
        const TKey& key,
        Timestamp timestamp,
        const std::optional<TValue>& prev_value,
        Step prev_step) {
        if (prev_value) {
            DomainPutQuery<TKeyEncoder, RawEncoder<ByteView>> query{tx, entity};
            query.exec(key, ByteView{}, timestamp, prev_value, prev_step);
        }
    }
};

}  // namespace silkworm::datastore::kvdb
