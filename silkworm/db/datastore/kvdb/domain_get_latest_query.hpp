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

#include <limits>
#include <optional>

#include "../common/step.hpp"
#include "domain.hpp"
#include "domain_codecs.hpp"
#include "mdbx.hpp"

namespace silkworm::datastore::kvdb {

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
        key_encoder.value.timestamp.value = Step{std::numeric_limits<decltype(Step::value)>::max()};
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

}  // namespace silkworm::datastore::kvdb
