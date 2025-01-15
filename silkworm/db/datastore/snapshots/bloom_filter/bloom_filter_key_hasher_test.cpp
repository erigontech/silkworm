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

#include "bloom_filter_key_hasher.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::snapshots::bloom_filter {

TEST_CASE("BloomFilterKeyHasher") {
    CHECK(BloomFilterKeyHasher{0}.hash(*from_hex("CAFEBABE")) == 2809309899937206063u);
    CHECK(BloomFilterKeyHasher{12345}.hash(*from_hex("56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421")) == 17810263873480351644u);
}

}  // namespace silkworm::snapshots::bloom_filter
