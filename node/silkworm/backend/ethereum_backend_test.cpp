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
#include <silkworm/common/directories.hpp>
#include <silkworm/db/mdbx.hpp>

namespace silkworm {

using namespace evmc::literals;

TEST_CASE("EthereumBackEnd", "[silkworm][backend][ethereum_backend]") {
    const std::string kTestSentryAddress1{"127.0.0.1:112233"};
    const std::string kTestSentryAddress2{"127.0.0.1:332211"};

    TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path()};
    REQUIRE_NOTHROW(data_dir.deploy());
    db::EnvConfig db_config{data_dir.chaindata().path().string()};
    db_config.create = true;
    db_config.inmemory = true;
    auto database_env = db::open_env(db_config);
    NodeSettings node_settings;

    SECTION("EthereumBackEnd::EthereumBackEnd", "[silkworm][backend][ethereum_backend]") {
        EthereumBackEnd backend{node_settings, &database_env};
        CHECK(backend.node_name() == kDefaultNodeName);
        CHECK(!backend.etherbase());
        CHECK(backend.sentry_addresses().size() == 1);
        CHECK(backend.state_change_source() != nullptr);
    }

    SECTION("EthereumBackEnd::set_node_name", "[silkworm][backend][ethereum_backend]") {
        const std::string node_name{"server_name"};
        EthereumBackEnd backend{node_settings, &database_env};
        backend.set_node_name(node_name);
        CHECK(backend.node_name() == node_name);
    }

    SECTION("EthereumBackEnd::etherbase", "[silkworm][backend][ethereum_backend]") {
        node_settings.etherbase = 0xd4fe7bc31cedb7bfb8a345f31e668033056b2728_address;
        EthereumBackEnd backend{node_settings, &database_env};
        CHECK(backend.etherbase() == 0xd4fe7bc31cedb7bfb8a345f31e668033056b2728_address);
    }

    SECTION("EthereumBackEnd::sentry_addresses default", "[silkworm][backend][ethereum_backend]") {
        EthereumBackEnd backend{node_settings, &database_env};
        CHECK(backend.sentry_addresses().size() == 1);
    }

    SECTION("EthereumBackEnd::sentry_addresses one", "[silkworm][backend][ethereum_backend]") {
        node_settings.external_sentry_addr = kTestSentryAddress1;
        EthereumBackEnd backend{node_settings, &database_env};
        CHECK(backend.sentry_addresses() == std::vector<std::string>{kTestSentryAddress1});
    }

    SECTION("EthereumBackEnd::sentry_addresses two", "[silkworm][backend][ethereum_backend]") {
        node_settings.external_sentry_addr = kTestSentryAddress1 + "," + kTestSentryAddress2;
        EthereumBackEnd backend{node_settings, &database_env};
        CHECK(backend.sentry_addresses() == std::vector<std::string>{kTestSentryAddress1, kTestSentryAddress2});
    }

    SECTION("EthereumBackEnd::close", "[silkworm][backend][ethereum_backend]") {
        EthereumBackEnd backend{node_settings, &database_env};
        CHECK_NOTHROW(backend.close());
    }
}

}  // namespace silkworm
