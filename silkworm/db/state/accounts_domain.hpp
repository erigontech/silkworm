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
#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>
#include <silkworm/infra/common/decoding_exception.hpp>

#include "address_decoder.hpp"

namespace silkworm::db::state {

struct AccountDecoder : public snapshots::Decoder {
    Account value;

    ~AccountDecoder() override = default;

    void decode_word(ByteView word) override {
        auto account = Account::from_encoded_storage_v3(word);
        if (!account)
            throw DecodingException{account.error(), "AccountDecoder failed to decode Account"};
        value = std::move(*account);
    }
};

static_assert(snapshots::DecoderConcept<AccountDecoder>);

using AccountsDomainKVSegmentReader = snapshots::segment::KVSegmentReader<AddressDecoder, AccountDecoder>;

}  // namespace silkworm::db::state
