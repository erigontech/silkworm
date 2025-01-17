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

#include <silkworm/core/types/account.hpp>
#include <silkworm/db/datastore/kvdb/codec.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

#include "account_codec.hpp"
#include "silkworm/db/util.hpp"

namespace silkworm::db::state {

struct AccountKVDBCodec : public datastore::kvdb::Codec {
    Account value;
    Bytes data;

    ~AccountKVDBCodec() override = default;

    datastore::kvdb::Slice encode() override {
        data = AccountCodec::encode_for_storage_v3(value);
        return datastore::kvdb::to_slice(data);
    }

    void decode(datastore::kvdb::Slice slice) override {
        value = unwrap_or_throw(AccountCodec::from_encoded_storage_v3(datastore::kvdb::from_slice(slice)));
    }
};

static_assert(datastore::kvdb::EncoderConcept<AccountKVDBCodec>);
static_assert(datastore::kvdb::DecoderConcept<AccountKVDBCodec>);

struct AccountSnapshotsCodec : public snapshots::Codec {
    Account value;
    Bytes word;

    ~AccountSnapshotsCodec() override = default;

    ByteView encode_word() override {
        word = AccountCodec::encode_for_storage_v3(value);
        return word;
    }

    void decode_word(ByteView input_word) override {
        auto account = AccountCodec::from_encoded_storage_v3(input_word);
        if (!account)
            throw DecodingException{account.error(), "AccountSnapshotsCodec failed to decode Account"};
        value = *account;
    }
};

static_assert(snapshots::EncoderConcept<AccountSnapshotsCodec>);
static_assert(snapshots::DecoderConcept<AccountSnapshotsCodec>);

}  // namespace silkworm::db::state
