// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/types/account.hpp>
#include <silkworm/db/datastore/kvdb/codec.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

#include "account_codec.hpp"
#include "silkworm/db/util.hpp"

namespace silkworm::db::state {

struct AccountKVDBCodec : public datastore::kvdb::Codec {
    std::optional<Account> value;
    Bytes data;

    ~AccountKVDBCodec() override = default;

    datastore::kvdb::Slice encode() override {
        if (value) {
            data = AccountCodec::encode_for_storage_v3(*value);
        } else {
            data.clear();
        }
        return datastore::kvdb::to_slice(data);
    }

    void decode(datastore::kvdb::Slice slice) override {
        if (!slice.empty()) {
            value = unwrap_or_throw(AccountCodec::from_encoded_storage_v3(datastore::kvdb::from_slice(slice)),
                                    "AccountKVDBCodec failed to decode Account");
        } else {
            value.reset();
        }
    }
};

static_assert(datastore::kvdb::EncoderConcept<AccountKVDBCodec>);
static_assert(datastore::kvdb::DecoderConcept<AccountKVDBCodec>);

struct AccountSnapshotsCodec : public snapshots::Codec {
    std::optional<Account> value;
    Bytes word;

    ~AccountSnapshotsCodec() override = default;

    ByteView encode_word() override {
        if (value) {
            word = AccountCodec::encode_for_storage_v3(*value);
        } else {
            word.clear();
        }
        return word;
    }

    void decode_word(Word& input_word) override {
        const ByteView input_word_view = input_word;
        if (!input_word_view.empty()) {
            value = unwrap_or_throw(AccountCodec::from_encoded_storage_v3(input_word_view),
                                    "AccountSnapshotsCodec failed to decode Account");
        } else {
            value.reset();
        }
    }
};

static_assert(snapshots::EncoderConcept<AccountSnapshotsCodec>);
static_assert(snapshots::DecoderConcept<AccountSnapshotsCodec>);

}  // namespace silkworm::db::state
