// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "storage_domain.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

using evmc::literals::operator""_address;
using evmc::literals::operator""_bytes32;
const evmc::bytes32 kFullWord{0x010000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
const evmc::bytes32 kPartialWord{0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
const evmc::bytes32 kEmptyWord{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};

using Word = snapshots::Decoder::Word;

TEST_CASE("Bytes32KVDBCodec.full_word") {
    Bytes32KVDBCodec codec;
    codec.value = kFullWord;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == kFullWord);
}

TEST_CASE("Bytes32KVDBCodec.partial_word") {
    Bytes32KVDBCodec codec;
    codec.value = kPartialWord;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == kPartialWord);
}

TEST_CASE("Bytes32KVDBCodec.empty_word") {
    Bytes32KVDBCodec codec;
    codec.value = kEmptyWord;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == kEmptyWord);
}

TEST_CASE("PackedBytes32KVDBCodec.full_word") {
    PackedBytes32KVDBCodec codec;
    codec.value = kFullWord;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    PackedBytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == kFullWord);
}

TEST_CASE("PackedBytes32KVDBCodec.partial_word") {
    PackedBytes32KVDBCodec codec;
    codec.value = kPartialWord;
    auto slice = codec.encode();
    CHECK(slice.size() == 10);

    PackedBytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == kPartialWord);
}

TEST_CASE("PackedBytes32KVDBCodec.empty_word") {
    PackedBytes32KVDBCodec codec;
    codec.value = kEmptyWord;
    auto slice = codec.encode();
    CHECK(slice.empty());

    PackedBytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == kEmptyWord);
}

TEST_CASE("StorageAddressAndLocationKVDBEncoder.encode") {
    StorageAddressAndLocationKVDBEncoder encoder;

    encoder.value.address = 0x000000000000000000636f6e736f6c652e6c6f67_address;
    encoder.value.location_hash = 0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32;
    auto encoded_view = silkworm::datastore::kvdb::from_slice(encoder.encode());
    CHECK(
        encoded_view ==
        *from_hex(
            "000000000000000000636f6e736f6c652e6c6f67"
            "000000000000000000000000000000000000000000005666856076ebaf477f07"));
}

TEST_CASE("Bytes32SnapshotsCodec.full_word") {
    Bytes32SnapshotsCodec codec;
    codec.value = kFullWord;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    Bytes32SnapshotsCodec codec2;
    Word encoded_bytes{encoded};
    codec2.decode_word(encoded_bytes);
    CHECK(codec2.value == kFullWord);
}

TEST_CASE("Bytes32SnapshotsCodec.partial_word") {
    Bytes32SnapshotsCodec codec;
    codec.value = kPartialWord;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    Bytes32SnapshotsCodec codec2;
    Word encoded_bytes{encoded};
    codec2.decode_word(encoded_bytes);
    CHECK(codec2.value == kPartialWord);
}

TEST_CASE("Bytes32SnapshotsCodec.empty_word") {
    Bytes32SnapshotsCodec codec;
    codec.value = kEmptyWord;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    Bytes32SnapshotsCodec codec2;
    Word encoded_bytes{encoded};
    codec2.decode_word(encoded_bytes);
    CHECK(codec2.value == kEmptyWord);
}

TEST_CASE("PackedBytes32SnapshotsCodec.full_word") {
    PackedBytes32SnapshotsCodec codec;
    codec.value = kFullWord;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    PackedBytes32SnapshotsCodec codec2;
    Word encoded_bytes{encoded};
    codec2.decode_word(encoded_bytes);
    CHECK(codec2.value == kFullWord);
}

TEST_CASE("PackedBytes32SnapshotsCodec.partial_word") {
    PackedBytes32SnapshotsCodec codec;
    codec.value = kPartialWord;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 10);

    PackedBytes32SnapshotsCodec codec2;
    Word encoded_bytes{encoded};
    codec2.decode_word(encoded_bytes);
    CHECK(codec2.value == kPartialWord);
}

TEST_CASE("PackedBytes32SnapshotsCodec.empty_word") {
    PackedBytes32SnapshotsCodec codec;
    codec.value = kEmptyWord;
    auto encoded = codec.encode_word();
    CHECK(encoded.empty());

    PackedBytes32SnapshotsCodec codec2;
    Word encoded_bytes{encoded};
    codec2.decode_word(encoded_bytes);
    CHECK(codec2.value == kEmptyWord);
}

TEST_CASE("StorageAddressAndLocationSnapshotsCodec.decode_word") {
    StorageAddressAndLocationSnapshotsCodec decoder;

    Word word{*from_hex(
        "000000000000000000636f6e736f6c652e6c6f67"
        "000000000000000000000000000000000000000000005666856076ebaf477f07")};
    decoder.decode_word(word);
    CHECK(decoder.value.address == 0x000000000000000000636f6e736f6c652e6c6f67_address);
    CHECK(decoder.value.location_hash == 0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32);

    Word empty;
    CHECK_THROWS_AS(decoder.decode_word(empty), std::runtime_error);
}

TEST_CASE("StorageAddressAndLocationSnapshotsCodec.encode_word") {
    StorageAddressAndLocationSnapshotsCodec encoder;

    encoder.value.address = 0x000000000000000000636f6e736f6c652e6c6f67_address;
    encoder.value.location_hash = 0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32;
    CHECK(
        encoder.encode_word() ==
        *from_hex(
            "000000000000000000636f6e736f6c652e6c6f67"
            "000000000000000000000000000000000000000000005666856076ebaf477f07"));
}

}  // namespace silkworm::db::state
