// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "domain_put_query.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainDeleteQuery {
    RWTxn& tx;
    Domain entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueEncoder::value);

    void exec(
        const Key& key,
        Timestamp timestamp,
        const std::optional<Value>& prev_value,
        Step current_step) {
        if (prev_value) {
            TValueEncoder prev_value_encoder;
            prev_value_encoder.value = std::move(*prev_value);
            Slice prev_value_slice = prev_value_encoder.encode();

            RawDecoder<ByteView> prev_value_slice_decoder;
            prev_value_slice_decoder.decode(prev_value_slice);
            ByteView prev_value_data = prev_value_slice_decoder.value;

            DomainPutQuery<TKeyEncoder, RawEncoder<ByteView>> query{tx, entity};
            query.exec(key, ByteView{}, timestamp, prev_value_data, current_step);
        }
    }
};

}  // namespace silkworm::datastore::kvdb
