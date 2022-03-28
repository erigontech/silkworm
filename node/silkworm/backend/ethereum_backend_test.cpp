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

#include "ethereum_backend.hpp"

#include <catch2/catch.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("EthereumBackEnd::EthereumBackEnd", "[silkworm][backend][ethereum_backend]") {
    EthereumBackEnd backend{};
    CHECK(backend.node_name() == kDefaultNodeName);
    CHECK(!backend.etherbase());
    CHECK(backend.sentry_addresses().empty());
}

TEST_CASE("ServerConfig::set_node_name", "[silkworm][backend][ethereum_backend]") {
    const std::string node_name{"server_name"};
    EthereumBackEnd backend;
    backend.set_node_name(node_name);
    CHECK(backend.node_name() == node_name);
}

TEST_CASE("ServerConfig::set_etherbase", "[silkworm][backend][ethereum_backend]") {
    const evmc::address etherbase{0xd4fe7bc31cedb7bfb8a345f31e668033056b2728_address};
    EthereumBackEnd backend;
    backend.set_etherbase(etherbase);
    CHECK(backend.etherbase() == 0xd4fe7bc31cedb7bfb8a345f31e668033056b2728_address);
}

TEST_CASE("ServerConfig::add_sentry_address", "[silkworm][backend][ethereum_backend]") {
    const std::string address_uri1{"127.0.0.1:112233"};
    const std::string address_uri2{"127.0.0.1:332211"};
    EthereumBackEnd backend;
    REQUIRE(backend.sentry_addresses().empty());
    backend.add_sentry_address(address_uri1);
    CHECK(backend.sentry_addresses() == std::vector<std::string>{address_uri1});
    backend.add_sentry_address(address_uri2);
    CHECK(backend.sentry_addresses() == std::vector<std::string>{address_uri1, address_uri2});
}

} // namespace silkworm
