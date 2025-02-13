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

#include "storage_domain.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

using evmc::literals::operator""_address;
using evmc::literals::operator""_bytes32;
const evmc::bytes32 full_word{0x010000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
const evmc::bytes32 partial_word{0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32};
const evmc::bytes32 empty_word{0x0000000000000000000000000000000000000000000000000000000000000000_bytes32};

TEST_CASE("Bytes32KVDBCodec.full_word") {
    Bytes32KVDBCodec codec;
    codec.value = full_word;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == full_word);
}

TEST_CASE("Bytes32KVDBCodec.partial_word") {
    Bytes32KVDBCodec codec;
    codec.value = partial_word;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == partial_word);
}

TEST_CASE("Bytes32KVDBCodec.empty_word") {
    Bytes32KVDBCodec codec;
    codec.value = empty_word;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == empty_word);
}

TEST_CASE("PackedBytes32KVDBCodec.full_word") {
    PackedBytes32KVDBCodec codec;
    codec.value = full_word;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    PackedBytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == full_word);
}

TEST_CASE("PackedBytes32KVDBCodec.partial_word") {
    PackedBytes32KVDBCodec codec;
    codec.value = partial_word;
    auto slice = codec.encode();
    CHECK(slice.size() == 10);

    PackedBytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == partial_word);
}

TEST_CASE("PackedBytes32KVDBCodec.empty_word") {
    PackedBytes32KVDBCodec codec;
    codec.value = empty_word;
    auto slice = codec.encode();
    CHECK(slice.size() == 0);

    PackedBytes32KVDBCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == empty_word);
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
    codec.value = full_word;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    Bytes32SnapshotsCodec codec2;
    codec2.decode_word(encoded);
    CHECK(codec2.value == full_word);
}

TEST_CASE("Bytes32SnapshotsCodec.partial_word") {
    Bytes32SnapshotsCodec codec;
    codec.value = partial_word;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    Bytes32SnapshotsCodec codec2;
    codec2.decode_word(encoded);
    CHECK(codec2.value == partial_word);
}

TEST_CASE("Bytes32SnapshotsCodec.empty_word") {
    Bytes32SnapshotsCodec codec;
    codec.value = empty_word;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    Bytes32SnapshotsCodec codec2;
    codec2.decode_word(encoded);
    CHECK(codec2.value == empty_word);
}

TEST_CASE("PackedBytes32SnapshotsCodec.full_word") {
    PackedBytes32SnapshotsCodec codec;
    codec.value = full_word;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 32);

    PackedBytes32SnapshotsCodec codec2;
    codec2.decode_word(encoded);
    CHECK(codec2.value == full_word);
}

TEST_CASE("PackedBytes32SnapshotsCodec.partial_word") {
    PackedBytes32SnapshotsCodec codec;
    codec.value = partial_word;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 10);

    PackedBytes32SnapshotsCodec codec2;
    codec2.decode_word(encoded);
    CHECK(codec2.value == partial_word);
}

TEST_CASE("PackedBytes32SnapshotsCodec.empty_word") {
    PackedBytes32SnapshotsCodec codec;
    codec.value = empty_word;
    auto encoded = codec.encode_word();
    CHECK(encoded.size() == 0);

    PackedBytes32SnapshotsCodec codec2;
    codec2.decode_word(encoded);
    CHECK(codec2.value == empty_word);
}

TEST_CASE("StorageAddressAndLocationSnapshotsCodec.decode_word") {
    StorageAddressAndLocationSnapshotsCodec decoder;

    decoder.decode_word(
        *from_hex(
            "000000000000000000636f6e736f6c652e6c6f67"
            "000000000000000000000000000000000000000000005666856076ebaf477f07"));
    CHECK(decoder.value.address == 0x000000000000000000636f6e736f6c652e6c6f67_address);
    CHECK(decoder.value.location_hash == 0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32);

    CHECK_THROWS_AS(decoder.decode_word({}), std::runtime_error);
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
