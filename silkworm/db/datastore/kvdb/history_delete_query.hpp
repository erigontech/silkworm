// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "history_put_query.hpp"

namespace silkworm::datastore::kvdb {

template <EncoderConcept TKeyEncoder>
struct HistoryDeleteQuery {
    RWTxn& tx;
    History entity;

    using Key = decltype(TKeyEncoder::value);

    void exec(const Key& key, Timestamp timestamp) {
        HistoryPutQuery<TKeyEncoder, RawEncoder<ByteView>> query{tx, entity};
        query.exec(key, ByteView{}, timestamp);
    }
};

}  // namespace silkworm::datastore::kvdb
