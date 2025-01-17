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

#include "address_codecs.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

TEST_CASE("AddressSnapshotsDecoder") {
    using evmc::literals::operator""_address;
    AddressSnapshotsDecoder decoder;
    decoder.decode_word(*from_hex("0x000000000000000000636f6e736f6c652e6c6f67"));
    CHECK(decoder.value == 0x000000000000000000636f6e736f6c652e6c6f67_address);

    CHECK_THROWS_AS(decoder.decode_word({}), std::runtime_error);
}

TEST_CASE("AddressSnapshotsEncoder") {
    using evmc::literals::operator""_address;
    AddressSnapshotsEncoder encoder;
    encoder.value = 0x000000000000000000636f6e736f6c652e6c6f67_address;
    CHECK(encoder.encode_word() == *from_hex("0x000000000000000000636f6e736f6c652e6c6f67"));
}

}  // namespace silkworm::db::state
