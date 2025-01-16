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

#include <cstring>
#include <stdexcept>

#include "address_codecs.hpp"

namespace silkworm::db::state {

struct Bytes32KVDBCodec : public datastore::kvdb::Codec {
    evmc::bytes32 value;
    ~Bytes32KVDBCodec() override = default;
    datastore::kvdb::Slice encode() override {
        return {&value.bytes, sizeof(value.bytes)};
    }
    void decode(datastore::kvdb::Slice slice) override {
        SILKWORM_ASSERT(slice.size() >= sizeof(value.bytes));
        std::memcpy(value.bytes, slice.data(), sizeof(value.bytes));
    }
};

static_assert(datastore::kvdb::EncoderConcept<Bytes32KVDBCodec>);
static_assert(datastore::kvdb::DecoderConcept<Bytes32KVDBCodec>);

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

struct StorageAddressAndLocationKVDBEncoder : public datastore::kvdb::Encoder {
    struct {
        evmc::address address;
        evmc::bytes32 location_hash;
    } value;

    struct {
        AddressKVDBEncoder address;
        Bytes32KVDBCodec location_hash;
    } encoder;

    Bytes data;

    ~StorageAddressAndLocationKVDBEncoder() override = default;

    datastore::kvdb::Slice encode() override;
};

static_assert(datastore::kvdb::EncoderConcept<StorageAddressAndLocationKVDBEncoder>);

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

}  // namespace silkworm::db::state
