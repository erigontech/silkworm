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

TEST_CASE("Bytes32NoLeadingZerosCodec.full_word") {
    using evmc::literals::operator""_address;
    using evmc::literals::operator""_bytes32;

    auto value = 0x010000000000000000000000000000000000000000005666856076ebaf477f07_bytes32;

    Bytes32NoLeadingZerosCodec codec;
    codec.value = value;
    auto slice = codec.encode();
    CHECK(slice.size() == 32);

    Bytes32NoLeadingZerosCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == value);
}

TEST_CASE("Bytes32NoLeadingZerosCodec.partial_word") {
    using evmc::literals::operator""_address;
    using evmc::literals::operator""_bytes32;

    auto value = 0x000000000000000000000000000000000000000000005666856076ebaf477f07_bytes32;

    Bytes32NoLeadingZerosCodec codec;
    codec.value = value;
    auto slice = codec.encode();
    CHECK(slice.size() == 10);

    Bytes32NoLeadingZerosCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == value);
}

TEST_CASE("Bytes32NoLeadingZerosCodec.empty_word") {
    using evmc::literals::operator""_address;
    using evmc::literals::operator""_bytes32;

    auto value = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

    Bytes32NoLeadingZerosCodec codec;
    codec.value = value;
    auto slice = codec.encode();
    CHECK(slice.size() == 0);

    Bytes32NoLeadingZerosCodec codec2;
    codec2.decode(slice);
    CHECK(codec2.value == value);
}


TEST_CASE("StorageAddressAndLocationSnapshotsCodec.decode_word") {
    using evmc::literals::operator""_address;
    using evmc::literals::operator""_bytes32;
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
    using evmc::literals::operator""_address;
    using evmc::literals::operator""_bytes32;
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
