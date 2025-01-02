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

#include <stdexcept>

#include <evmc/evmc.hpp>

#include <silkworm/db/datastore/kvdb/codec.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>

namespace silkworm::db::state {

struct AddressKVDBEncoder : public datastore::kvdb::Encoder {
    evmc::address value;

    ~AddressKVDBEncoder() override = default;

    datastore::kvdb::Slice encode() override {
        return {&value.bytes, kAddressLength};
    }
};

static_assert(datastore::kvdb::EncoderConcept<AddressKVDBEncoder>);

struct AddressDecoder : public snapshots::Decoder {
    evmc::address value;

    ~AddressDecoder() override = default;

    void decode_word(ByteView word) override {
        if (word.size() < kAddressLength)
            throw std::runtime_error{"AddressDecoder failed to decode"};
        std::memcpy(value.bytes, word.data(), kAddressLength);
    }
};

static_assert(snapshots::DecoderConcept<AddressDecoder>);

}  // namespace silkworm::db::state
