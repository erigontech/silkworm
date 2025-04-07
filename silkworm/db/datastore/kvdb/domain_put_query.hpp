// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "domain_put_latest_query.hpp"
#include "history_delete_query.hpp"
#include "history_put_query.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder, EncoderConcept TValueEncoder>
struct DomainPutQuery {
    RWTxn& tx;
    Domain entity;

    using Key = decltype(TKeyEncoder::value);
    using Value = decltype(TValueEncoder::value);

    void exec(
        const Key& key,
        const Value& value,
        Timestamp timestamp,
        const std::optional<Value>& prev_value,
        Step current_step) {
        DomainPutLatestQuery<TKeyEncoder, TValueEncoder> value_query{tx, entity};
        value_query.exec(key, value, current_step);

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

}  // namespace silkworm::datastore::kvdb
