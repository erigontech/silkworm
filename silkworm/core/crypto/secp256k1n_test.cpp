/*
   Copyright 2025 The Silkworm Authors

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

#include "secp256k1n.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm {

TEST_CASE("is_valid_signature") {
    bool homestead = false;
    CHECK(!is_valid_signature(0, 0, homestead));
    CHECK(!is_valid_signature(0, 1, homestead));
    CHECK(!is_valid_signature(1, 0, homestead));
    CHECK(is_valid_signature(1, 1, homestead));
    CHECK(is_valid_signature(1, kSecp256k1Halfn, homestead));
    CHECK(is_valid_signature(1, kSecp256k1Halfn + 1, homestead));
    CHECK(is_valid_signature(kSecp256k1n - 1, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n - 1, kSecp256k1n, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n, homestead));

    homestead = true;
    CHECK(!is_valid_signature(0, 0, homestead));
    CHECK(!is_valid_signature(0, 1, homestead));
    CHECK(!is_valid_signature(1, 0, homestead));
    CHECK(is_valid_signature(1, 1, homestead));
    CHECK(is_valid_signature(1, kSecp256k1Halfn, homestead));
    CHECK(!is_valid_signature(1, kSecp256k1Halfn + 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n - 1, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n - 1, kSecp256k1n, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n - 1, homestead));
    CHECK(!is_valid_signature(kSecp256k1n, kSecp256k1n, homestead));
}

}  // namespace silkworm
