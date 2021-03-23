/*
Copyright (c) 2014, lamerman
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of lamerman nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "lru_cache.hpp"

#include <catch2/catch.hpp>

namespace silkworm {

TEST_CASE("SimplePut") {
    lru_cache<int, int> cache_lru(1);
    cache_lru.put(7, 777);
    REQUIRE(cache_lru.get(7));
    CHECK(777 == *cache_lru.get(7));
    CHECK(1 == cache_lru.size());
}

TEST_CASE("MissingValue") {
    lru_cache<int, int> cache_lru(1);
    CHECK(cache_lru.get(7) == nullptr);
}

TEST_CASE("KeepsAllValuesWithinCapacity") {
    static constexpr int NUM_OF_RECORDS = 100;
    static constexpr int CACHE_CAPACITY = 50;

    lru_cache<int, int> cache_lru(CACHE_CAPACITY);

    for (int i = 0; i < NUM_OF_RECORDS; ++i) {
        cache_lru.put(i, i);
    }

    for (int i = 0; i < NUM_OF_RECORDS - CACHE_CAPACITY; ++i) {
        CHECK(cache_lru.get(i) == nullptr);
    }

    for (int i = NUM_OF_RECORDS - CACHE_CAPACITY; i < NUM_OF_RECORDS; ++i) {
        REQUIRE(cache_lru.get(i));
        CHECK(i == *cache_lru.get(i));
    }

    size_t size = cache_lru.size();
    CHECK(CACHE_CAPACITY == size);
}

}  // namespace silkworm
