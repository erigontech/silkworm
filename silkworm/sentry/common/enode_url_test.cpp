// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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