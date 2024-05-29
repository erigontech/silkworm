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

#include "ecc_key_pair.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm::sentry {

TEST_CASE("EccKeyPair.public_key_hex") {
    CHECK(
        EccKeyPair(from_hex("289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032").value())
            .public_key()
            .hex() == "7db227d7094ce215c3a0f57e1bcc732551fe351f94249471934567e0f5dc1bf795962b8cccb87a2eb56b29fbe37d614e2f4c3c45b789ae4f1f51f4cb21972ffd");
    CHECK(
        EccKeyPair(from_hex("36a7edad64d51a568b00e51d3fa8cd340aa704153010edf7f55ab3066ca4ef21").value())
            .public_key()
            .hex() == "24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d");
}

}  // namespace silkworm::sentry
