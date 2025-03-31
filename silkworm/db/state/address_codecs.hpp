// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stdexcept>

#include <evmc/evmc.hpp>

#include <silkworm/db/datastore/kvdb/codec.hpp>
#include <silkworm/db/datastore/snapshots/common/codec.hpp>

namespace silkworm::db::state {

struct AddressKVDBCodec : public datastore::kvdb::Codec {
    evmc::address value;

    ~AddressKVDBCodec() override = default;

    datastore::kvdb::Slice encode() override {
        return {&value.bytes, kAddressLength};
    }

    void decode(datastore::kvdb::Slice slice) override {
        if (slice.size() < kAddressLength)
            throw std::runtime_error{"AddressKVDBDecoder failed to decode"};
        std::memcpy(value.bytes, slice.data(), kAddressLength);
    }
};

static_assert(datastore::kvdb::EncoderConcept<AddressKVDBCodec>);
static_assert(datastore::kvdb::EncoderConcept<AddressKVDBCodec>);

using AddressKVDBEncoder = AddressKVDBCodec;
using AddressKVDBDecoder = AddressKVDBCodec;

struct AddressSnapshotsCodec : public snapshots::Codec {
    evmc::address value;
    ~AddressSnapshotsCodec() override = default;

    ByteView encode_word() override {
        return ByteView{reinterpret_cast<uint8_t*>(&value.bytes), kAddressLength};
    }

    void decode_word(Word& word) override {
        const ByteView word_view = word;
        if (word_view.size() < kAddressLength)
            throw std::runtime_error{"AddressSnapshotsDecoder failed to decode"};
        std::memcpy(value.bytes, word_view.data(), kAddressLength);
    }
};

static_assert(snapshots::EncoderConcept<AddressSnapshotsCodec>);
static_assert(snapshots::DecoderConcept<AddressSnapshotsCodec>);

using AddressSnapshotsEncoder = AddressSnapshotsCodec;
using AddressSnapshotsDecoder = AddressSnapshotsCodec;

}  // namespace silkworm::db::state
