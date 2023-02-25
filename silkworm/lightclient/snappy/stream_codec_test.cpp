/*
   Copyright 2023 The Silkworm Authors

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

#include "stream_codec.hpp"

#include <algorithm>
#include <catch2/catch.hpp>

#include <silkworm/core/common/util.hpp>
#include <silkworm/lightclient/test/random.hpp>

namespace silkworm::snappy {

//! Build a byte sequence comprised of 10 alternating <block_size>-sized sequences of random (incompressible) bytes
//! and repeated (compressible) bytes to be used as input for Snappy codec roundtrip
static Bytes build_uncompressed(std::size_t uncompressed_size) {
    Bytes src{};
    src.resize(uncompressed_size);
    for (size_t i{0}; i < 10; ++i) {
        const auto sequence_size = uncompressed_size / 10;
        if (i % 2 == 0) {
            for (size_t j{0}; j < sequence_size; ++j) {
                src[sequence_size * i + j] = uint8_t(test::random_int(256));
            }
        } else {
            for (size_t j{0}; j < sequence_size; ++j) {
                src[sequence_size * i + j] = uint8_t(i);
            }
        }
    }
    return src;
}

//! Check Snappy framing codec round-trip (src->enc->dec->dst: dst=?src) applied to input sequence
static bool framing_roundtrip(ByteView src) {
    const auto compressed = framing_compress(src);
    const auto dst = framing_uncompress(compressed);
    if (dst.size() != src.size()) return false;
    return dst == src;
}

//! Special Snappy framed stream comprised by one stream identifier
const Bytes kSingleStreamIdentifier{kMagicChunk.cbegin(), kMagicChunk.cend()};

TEST_CASE("Snappy: Framing format") {
    SECTION("empty uncompressed is valid") {
        CHECK(framing_compress(Bytes{}) == kSingleStreamIdentifier);
    }
    SECTION("empty compressed is invalid") {
        CHECK_THROWS(framing_uncompress(Bytes{}));
    }
    SECTION("small copy") {
        for (std::size_t i{0}; i < 32; ++i) {
            std::string s = "aaaa" + std::string(i, 'b') + "aaaabbbb";
            Bytes src_bytes{s.cbegin(), s.cend()};
            CHECK(framing_roundtrip(src_bytes));
        }
    }
    SECTION("smaller than maxBlockSize") {
        Bytes src = build_uncompressed(1'000);
        CHECK(framing_roundtrip(src));
    }
    SECTION("equal to maxBlockSize") {
        const Bytes src = build_uncompressed(kMaxBlockSize);
        CHECK(framing_roundtrip(src));
    }
    /*SECTION("larger than maxBlockSize") {
        // 1e6 was chosen because 1e6 / 10 = 1e5 is larger than max block size (64k)
        //8*kMaxBlockSize
        Bytes src = build_uncompressed(524288 + 13211 + 1);
        CHECK(framing_roundtrip(src));
    }*/
    SECTION("single stream identifier") {
        CHECK(framing_uncompress(kSingleStreamIdentifier).empty());
    }
    SECTION("multiple stream identifier") {
        Bytes multiple_stream_identifier;
        multiple_stream_identifier.append(kSingleStreamIdentifier);
        multiple_stream_identifier.append(kSingleStreamIdentifier);
        CHECK(framing_uncompress(multiple_stream_identifier).empty());
    }
}

}  // namespace silkworm::snappy
