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

#include <silkworm/core/types/evmc_bytes32.hpp>

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

struct PackedBytes32KVDBCodec : public datastore::kvdb::Codec {
    evmc::bytes32 value;
    ~PackedBytes32KVDBCodec() override = default;
    datastore::kvdb::Slice encode() override {
        return {silkworm::zeroless_view(value.bytes)};
    }
    void decode(datastore::kvdb::Slice slice) override {
        SILKWORM_ASSERT(slice.size() <= sizeof(value.bytes));
        value = to_bytes32(silkworm::datastore::kvdb::from_slice(slice));
    }
};
static_assert(datastore::kvdb::EncoderConcept<PackedBytes32KVDBCodec>);
static_assert(datastore::kvdb::DecoderConcept<PackedBytes32KVDBCodec>);

struct Bytes32SnapshotsCodec : public snapshots::Codec {
    evmc::bytes32 value;
    ~Bytes32SnapshotsCodec() override = default;
    ByteView encode_word() override {
        return ByteView{value.bytes};
    }
    void decode_word(Bytes& word) override {
        if (word.size() < sizeof(value.bytes))
            throw std::runtime_error{"Bytes32SnapshotsCodec failed to decode"};
        std::memcpy(value.bytes, word.data(), sizeof(value.bytes));
    }
};
static_assert(snapshots::EncoderConcept<Bytes32SnapshotsCodec>);
static_assert(snapshots::DecoderConcept<Bytes32SnapshotsCodec>);

struct PackedBytes32SnapshotsCodec : public snapshots::Codec {
    evmc::bytes32 value;
    ~PackedBytes32SnapshotsCodec() override = default;
    ByteView encode_word() override {
        return silkworm::zeroless_view(ByteView{value});
    }
    void decode_word(Bytes& word) override {
        if (word.size() > sizeof(value.bytes))
            throw std::runtime_error{"PackedBytes32SnapshotsCodec failed to decode"};
        value = silkworm::to_bytes32(word);  // TODO(canepat) can we save a copy here?
    }
};
static_assert(snapshots::EncoderConcept<PackedBytes32SnapshotsCodec>);
static_assert(snapshots::DecoderConcept<PackedBytes32SnapshotsCodec>);

struct StorageAddressAndLocation {
    evmc::address address;
    evmc::bytes32 location_hash;
};

struct StorageAddressAndLocationKVDBEncoder : public datastore::kvdb::Encoder {
    StorageAddressAndLocation value;

    struct {
        AddressKVDBEncoder address;
        Bytes32KVDBCodec location_hash;
    } encoder;

    Bytes data;

    ~StorageAddressAndLocationKVDBEncoder() override = default;

    datastore::kvdb::Slice encode() override;
};
static_assert(datastore::kvdb::EncoderConcept<StorageAddressAndLocationKVDBEncoder>);

struct StorageAddressAndLocationSnapshotsCodec : public snapshots::Codec {
    StorageAddressAndLocation value;

    struct {
        AddressSnapshotsCodec address;
        Bytes32SnapshotsCodec location_hash;
    } codec;

    Bytes word;

    ~StorageAddressAndLocationSnapshotsCodec() override = default;

    ByteView encode_word() override;
    void decode_word(Bytes& input_word) override;
};
static_assert(snapshots::EncoderConcept<StorageAddressAndLocationSnapshotsCodec>);
static_assert(snapshots::DecoderConcept<StorageAddressAndLocationSnapshotsCodec>);

}  // namespace silkworm::db::state
