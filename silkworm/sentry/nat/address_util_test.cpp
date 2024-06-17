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
