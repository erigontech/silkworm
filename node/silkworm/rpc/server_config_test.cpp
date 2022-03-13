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

#include "server_config.hpp"

#include <memory>

#include <catch2/catch.hpp>

#include <silkworm/common/base.hpp>

namespace silkworm::rpc {

TEST_CASE("ServerConfig::ServerConfig", "[silkworm][rpc][server_config]") {
    ServerConfig config;
    CHECK(config.node_name() == kDefaultNodeName);
    CHECK(config.address_uri() == kDefaultAddressUri);
    CHECK(config.num_contexts() == kDefaultNumContexts);
}

TEST_CASE("ServerConfig::set_node_name", "[silkworm][rpc][server_config]") {
    const std::string node_name{"server_name"};
    ServerConfig config;
    config.set_node_name(node_name);
    CHECK(config.node_name() == node_name);
}

TEST_CASE("ServerConfig::set_address_uri", "[silkworm][rpc][server_config]") {
    const std::string address_uri{"127.0.0.1:12345"};
    ServerConfig config;
    config.set_address_uri(address_uri);
    CHECK(config.address_uri() == address_uri);
}

TEST_CASE("ServerConfig::set_num_contexts", "[silkworm][rpc][server_config]") {
    const uint32_t num_contexts{10};
    ServerConfig config;
    config.set_num_contexts(num_contexts);
    CHECK(config.num_contexts() == num_contexts);
}

} // namespace silkworm::rpc
