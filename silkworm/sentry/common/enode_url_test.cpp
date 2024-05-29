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

#include "enode_url.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::sentry {

TEST_CASE("EnodeUrl") {
    EnodeUrl url1("enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@1.2.3.4:5");
    CHECK(url1.public_key().hex() == "24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d");
    CHECK(url1.ip().to_string() == "1.2.3.4");
    CHECK(url1.port_disc() == 5);
    CHECK(url1.port_rlpx() == 5);
    CHECK(url1.to_string() == "enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@1.2.3.4:5");

    CHECK_THROWS(EnodeUrl("http://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@1.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://xx@1.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://1.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@90000.2.3.4:5"));
    CHECK_THROWS(EnodeUrl("enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@localhost:5"));
    CHECK_THROWS(EnodeUrl("enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@1.2.3.4:x"));
    CHECK_THROWS(EnodeUrl("enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@1.2.3.4:90000"));
    CHECK_THROWS(EnodeUrl("enode://24bfa2cdce7c6a41184fa0809ad8d76969b7280952e9aa46179d90cfbab90f7d2b004928f0364389a1aa8d5166281f2ff7568493c1f719e8f6148ef8cf8af42d@1.2.3.4"));
}

}  // namespace silkworm::sentry