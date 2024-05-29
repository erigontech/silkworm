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

#include "hash.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("from_hex") {
    CHECK(Hash::from_hex("foo") == std::nullopt);

    const auto kHashValue{0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b_bytes32};
    CHECK(Hash::from_hex("0x2d690516512020171c1ec870f6ff45398cc8609250326be89915fb538e7b") == kHashValue);
}

}  // namespace silkworm
