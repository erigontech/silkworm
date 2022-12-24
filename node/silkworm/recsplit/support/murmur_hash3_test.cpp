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

#include "murmur_hash3.hpp"

#include <cstdint>
#include <cstring>
#include <memory>

#include <catch2/catch.hpp>

namespace silkworm::succinct {

using HashFunction = void (*)(const void*, uint64_t, uint32_t, void*);

static bool verification_test(HashFunction hash, const std::size_t hash_bits, int expected) {
    const auto hash_bytes = hash_bits / 8u;

    uint8_t* key{new uint8_t[256]};
    uint8_t* hashes{new uint8_t[hash_bytes * 256u]};
    uint8_t* res{new uint8_t[hash_bytes]};

    std::memset(key, 0, 256);
    std::memset(hashes, 0, hash_bytes * 256);
    std::memset(res, 0, hash_bytes);

    // Hash keys of the form {0}, {0,1}, {0,1,2}... up to N=255 using 256-N as the seed
    for (std::size_t i{0}; i < 256; ++i) {
        key[i] = static_cast<uint8_t>(i);
        hash(key, i, 256 - i, &hashes[i * hash_bytes]);
    }

    // Then hash the result array
    hash(hashes, hash_bytes * 256, 0, res);

    // The first four bytes of that hash, interpreted as a LE integer, is our verification value
    const int verification = (res[0] << 0) | (res[1] << 8) | (res[2] << 16) | (res[3] << 24);

    delete[] key;
    delete[] hashes;
    delete[] res;

    return verification == expected;
}

TEST_CASE("MurmurHash3_x64_128", "[silkworm][recsplit][support]") {
    CHECK(verification_test(MurmurHash3_x64_128, 128, 0x6384BA69));
}

TEST_CASE("Murmur3", "[silkworm][recsplit][support]") {
    Murmur3 hasher{42};
    uint8_t* key{new uint8_t[256]};
    uint8_t* hashed{new uint8_t[128]};

    CHECK_NOTHROW(hasher.hash_x64_128(key, 128, hashed));

    delete[] key;
    delete[] hashed;
}

}  // namespace silkworm::succinct
