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

#include <silkworm/db/datastore/snapshots/segment/kv_segment_reader.hpp>

#include "address_decoder.hpp"

namespace silkworm::db::state {

struct Bytes32Decoder : public snapshots::Decoder {
    evmc::bytes32 value;
    ~Bytes32Decoder() override = default;
    void decode_word(ByteView word) override {
        if (word.size() < sizeof(value.bytes))
            throw std::runtime_error{"Bytes32Decoder failed to decode"};
        std::memcpy(value.bytes, word.data(), sizeof(value.bytes));
    }
};

static_assert(snapshots::DecoderConcept<Bytes32Decoder>);

struct StorageAddressAndLocationDecoder : public snapshots::Decoder {
    struct {
        AddressDecoder address;
        Bytes32Decoder location_hash;
    } value;

    ~StorageAddressAndLocationDecoder() override = default;

    void decode_word(ByteView word) override {
        value.address.decode_word(word);
        value.location_hash.decode_word(word.substr(kAddressLength));
    }
};

static_assert(snapshots::DecoderConcept<StorageAddressAndLocationDecoder>);

using StorageDomainKVSegmentReader = snapshots::segment::KVSegmentReader<StorageAddressAndLocationDecoder, Bytes32Decoder>;

}  // namespace silkworm::db::state
