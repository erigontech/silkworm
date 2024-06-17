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

#include "bytes.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("Byteviews") {
    Bytes source{'0', '1', '2'};
    ByteView bv1(source);
    bv1.remove_prefix(3);
    REQUIRE(bv1.empty());
    ByteView bv2{};
    REQUIRE(bv2.empty());
    REQUIRE(bv1 == bv2);
    REQUIRE_FALSE(bv1.data() == bv2.data());
    REQUIRE(bv2.is_null());
}

}  // namespace silkworm
