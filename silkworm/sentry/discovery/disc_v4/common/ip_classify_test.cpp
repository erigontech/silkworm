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

#include "ip_classify.hpp"

#include <boost/asio/ip/address.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm::sentry::discovery::disc_v4::common {

using namespace boost::asio::ip;

TEST_CASE("ip_classify") {
    CHECK(ip_classify(make_address("23.55.1.242")) == IpAddressType::kRegular);
    CHECK(ip_classify(make_address("192.0.3.1")) == IpAddressType::kRegular);
    CHECK(ip_classify(make_address("1.0.0.0")) == IpAddressType::kRegular);
    CHECK(ip_classify(make_address("172.32.0.1")) == IpAddressType::kRegular);
    CHECK(ip_classify(make_address("fec0::2233")) == IpAddressType::kRegular);
    CHECK(ip_classify(make_address("0.2.0.8")) == IpAddressType::kRegular);

    CHECK(ip_classify(make_address("0.0.0.0")) == IpAddressType::kUnspecified);

    CHECK(ip_classify(make_address("127.0.0.1")) == IpAddressType::kLoopback);
    CHECK(ip_classify(make_address("127.0.2.19")) == IpAddressType::kLoopback);

    CHECK(ip_classify(make_address("224.0.0.22")) == IpAddressType::kMulticast);
    CHECK(ip_classify(make_address("ff05::1:3")) == IpAddressType::kMulticast);

    CHECK(ip_classify(make_address("255.255.255.255")) == IpAddressType::kBroadcast);

    CHECK(ip_classify(make_address("10.0.1.1")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("10.22.0.3")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("172.31.252.251")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("192.168.0.1")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("192.168.1.4")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("fe80::f4a1:8eff:fec5:9d9d")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("febf::ab32:2233")) == IpAddressType::kLAN);
    CHECK(ip_classify(make_address("fc00::4")) == IpAddressType::kLAN);

    CHECK(ip_classify(make_address("192.0.2.1")) == IpAddressType::kSpecial);
    CHECK(ip_classify(make_address("192.0.2.44")) == IpAddressType::kSpecial);
    CHECK(ip_classify(make_address("192.0.0.171")) == IpAddressType::kSpecial);
    CHECK(ip_classify(make_address("2001:db8:85a3:8d3:1319:8a2e:370:7348")) == IpAddressType::kSpecial);
}

}  // namespace silkworm::sentry::discovery::disc_v4::common
