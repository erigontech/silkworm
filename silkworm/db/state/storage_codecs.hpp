// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
    void decode_word(Word& word) override {
        const ByteView word_view = word;
        if (word_view.size() < sizeof(value.bytes))
            throw std::runtime_error{"Bytes32SnapshotsCodec failed to decode"};
        std::memcpy(value.bytes, word_view.data(), sizeof(value.bytes));
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
    void decode_word(Word& word) override {
        const ByteView word_view = word;
        if (word_view.size() > sizeof(value.bytes))
            throw std::runtime_error{"PackedBytes32SnapshotsCodec failed to decode"};
        value = silkworm::to_bytes32(word_view);
    }
};
static_assert(snapshots::EncoderConcept<PackedBytes32SnapshotsCodec>);
static_assert(snapshots::DecoderConcept<PackedBytes32SnapshotsCodec>);

#pragma pack(push)
#pragma pack(1)
struct StorageAddressAndLocation {
    evmc::address address;
    evmc::bytes32 location_hash;
};
#pragma pack(pop)

struct StorageAddressAndLocationKVDBCodec : public datastore::kvdb::Codec {
    StorageAddressAndLocation value;

    struct {
        AddressKVDBCodec address;
        Bytes32KVDBCodec location_hash;
    } codec;

    ~StorageAddressAndLocationKVDBCodec() override = default;

    datastore::kvdb::Slice encode() override;
    void decode(datastore::kvdb::Slice slice) override;
};
static_assert(datastore::kvdb::EncoderConcept<StorageAddressAndLocationKVDBCodec>);
static_assert(datastore::kvdb::DecoderConcept<StorageAddressAndLocationKVDBCodec>);
using StorageAddressAndLocationKVDBEncoder = StorageAddressAndLocationKVDBCodec;
using StorageAddressAndLocationKVDBDecoder = StorageAddressAndLocationKVDBCodec;

struct StorageAddressAndLocationSnapshotsCodec : public snapshots::Codec {
    StorageAddressAndLocation value;

    struct {
        AddressSnapshotsCodec address;
        Bytes32SnapshotsCodec location_hash;
    } codec;

    ~StorageAddressAndLocationSnapshotsCodec() override = default;

    ByteView encode_word() override;
    void decode_word(Word& input_word) override;
};
static_assert(snapshots::EncoderConcept<StorageAddressAndLocationSnapshotsCodec>);
static_assert(snapshots::DecoderConcept<StorageAddressAndLocationSnapshotsCodec>);

}  // namespace silkworm::db::state
