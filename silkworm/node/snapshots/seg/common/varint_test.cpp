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

#include "varint.hpp"

#include <limits>
#include <vector>

#include <catch2/catch.hpp>

namespace silkworm::snapshots::seg {

TEST_CASE("varint") {
    Bytes buffer;

    std::vector<uint64_t> examples = {
        0,
        1,
        2,
        127,
        128,
        150,
        256,
        std::numeric_limits<uint32_t>::max(),
        std::numeric_limits<uint64_t>::max(),
    };

    for (uint64_t example : examples) {
        ByteView encoded = varint::encode(buffer, example);
        CHECK(varint::decode(encoded) == example);
    }
}

TEST_CASE("varint.size") {
    Bytes buffer;
    ByteView encoded;

    encoded = varint::encode(buffer, 150);
    CHECK(encoded.size() == 2);
    encoded = buffer;
    varint::decode(encoded);
    CHECK(encoded.size() == buffer.size() - 2);

    encoded = varint::encode(buffer, 2048383);
    CHECK(encoded.size() == 3);
    encoded = buffer;
    varint::decode(encoded);
    CHECK(encoded.size() == buffer.size() - 3);
}

TEST_CASE("varint.too_long") {
    Bytes buffer;
    ByteView encoded;

    encoded = varint::encode(buffer, std::numeric_limits<uint64_t>::max());
    CHECK(encoded.size() == buffer.size());
    buffer[buffer.size() - 1] = 0xFF;
    CHECK_FALSE(varint::decode(encoded).has_value());
    CHECK(encoded.size() == buffer.size());

    encoded = varint::encode(buffer, 150);
    CHECK(encoded.size() == 2);
    encoded.remove_suffix(1);
    CHECK_FALSE(varint::decode(encoded).has_value());
    CHECK(encoded.size() == 1);
}

}  // namespace silkworm::snapshots::seg
