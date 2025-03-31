// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "address_util.hpp"

#include <catch2/catch_test_macros.hpp>

namespace silkworm::sentry::nat {

TEST_CASE("make_address_from_sockaddr.v4.localhost") {
    sockaddr_in localhost_addr{};
    localhost_addr.sin_family = AF_INET;
    localhost_addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    CHECK(make_address_from_sockaddr(reinterpret_cast<sockaddr*>(&localhost_addr)).to_string() == "127.0.0.1");
}

TEST_CASE("make_address_from_sockaddr.v6.localhost") {
    sockaddr_in6 localhost_addr{};
    localhost_addr.sin6_family = AF_INET6;
    localhost_addr.sin6_addr = in6addr_loopback;

    CHECK(make_address_from_sockaddr(reinterpret_cast<sockaddr*>(&localhost_addr)).to_string() == "::1");
}

}  // namespace silkworm::sentry::nat
