/*
   Copyright 2022 The Silkworm Authors

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

#include "snappy_codec.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/util.hpp>

namespace silkworm::snappy {

TEST_CASE("Snappy") {
    const Bytes kUncompressed{*from_hex(
        "2a817b45ec456cfe6327b70769498f51ffffffffffffffffffffffffffffffff"
        "ffffffffffffffffffffffffffffffff000000000000000053bee62ce3d5c7b0"
        "155f00a78a500adea9948ae94b84839274147021d817c0800c6e7696ad677d96"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")};
    const Bytes kInvalidCompressed{*from_hex(
        "8001402a817b45ec456cfe6327b70769498f51ff7a010000000d01a853bee62c"
        "e3d5c7b0155f00a78a500adea9948ae94b84839274147021d817c0800c6e7696"
        "ad677d96ffffff720200")};
    const Bytes kCompressed{*from_hex(
        "8001402a817b45ec456cfe6327b70769498f51ff7a010000000d01a053bee62c"
        "e3d5c7b0155f00a78a500adea9948ae94b84839274147021d817c0800c6e7696"
        "ad677d96ff7a5000")};

    SECTION("is_valid_compressed_data") {
        CHECK(is_valid_compressed_data(kCompressed));
        CHECK(!is_valid_compressed_data(kInvalidCompressed));
        // The following check *should* be OK but currently is *KO*: it seems a bug in C++ snappy library
        // CHECK(!::snappy::IsValidCompressedBuffer(reinterpret_cast<const char*>(kInvalidCompressed.data()), kInvalidCompressed.size()));
    }

    SECTION("compression") {
        Bytes compressed_output = snappy::compress(kUncompressed);
        CHECK(compressed_output == kCompressed);
    }

    SECTION("decompression") {
        Bytes uncompressed_output = snappy::decompress(kCompressed);
        CHECK(uncompressed_output == kUncompressed);
        // The following check *should* be OK but currently is *KO*: it seems a bug in C++ snappy library
        // CHECK_THROWS_AS(snappy::decompress(kInvalidCompressed), std::runtime_error);
    }

    SECTION("round-trip: decompress->compress") {
        Bytes uncompressed_output = snappy::decompress(kCompressed);
        CHECK(uncompressed_output == kUncompressed);
        Bytes compressed_output = snappy::compress(uncompressed_output);
        CHECK(compressed_output == kCompressed);
    }

    SECTION("round-trip: compress->decompress") {
        Bytes compressed_output = snappy::compress(kUncompressed);
        CHECK(compressed_output == kCompressed);
        Bytes uncompressed_output = snappy::decompress(compressed_output);
        CHECK(uncompressed_output == kUncompressed);
    }
}

}  // namespace silkworm::snappy
