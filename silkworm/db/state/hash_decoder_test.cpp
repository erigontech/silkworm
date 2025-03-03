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

#include "hash_decoder.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::db::state {

TEST_CASE("HashSnapshotsDecoder") {
    using evmc::literals::operator""_bytes32;
    HashSnapshotsDecoder decoder;
    auto word = *from_hex("0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55");
    decoder.decode_word(word);
    CHECK(decoder.value == 0xb397a22bb95bf14753ec174f02f99df3f0bdf70d1851cdff813ebf745f5aeb55_bytes32);

    Bytes empty;
    CHECK_THROWS_AS(decoder.decode_word(empty), std::runtime_error);
}

}  // namespace silkworm::db::state
