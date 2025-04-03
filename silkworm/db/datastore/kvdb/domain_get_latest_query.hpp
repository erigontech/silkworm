// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    ROTxn& tx;
    Domain entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueDecoder::value);

    struct Result {
        Value value;
        Step step{0};
    };

    std::optional<Result> exec(const Key& key) {
        DomainKeyEncoder<TKeyEncoder> key_encoder{/* has_large_values = */ false};
        key_encoder.value.key.value = key;
        key_encoder.value.timestamp.value = Step{std::numeric_limits<decltype(Step::value)>::max()};  // we need all 1s here
        Slice key_slice = key_encoder.encode();

        auto db_cursor = tx.ro_cursor(entity.values_table);
        auto result = entity.has_large_values ? db_cursor->lower_bound(key_slice, false) : db_cursor->find(key_slice, false);

        if (!result) {
            return std::nullopt;
        }

        DomainKeyDecoder<RawDecoder<ByteView>> key_decoder{entity.has_large_values};
        key_decoder.decode(result.key);
        if (key_decoder.value.key.value != from_slice(key_slice)) {
            return std::nullopt;
        }

        DomainValueDecoder<RawDecoder<ByteView>> empty_value_decoder{entity.has_large_values};
        empty_value_decoder.decode(result.value);
        if (empty_value_decoder.value.value.value.empty()) {
            return std::nullopt;
        }

        DomainValueDecoder<TValueDecoder> value_decoder{entity.has_large_values};
        value_decoder.decode(result.value);

        Step step = Step(key_decoder.value.timestamp.value.value | value_decoder.value.timestamp.value.value);

        return Result{std::move(value_decoder.value.value.value), step};
    }
};

}  // namespace silkworm::datastore::kvdb
