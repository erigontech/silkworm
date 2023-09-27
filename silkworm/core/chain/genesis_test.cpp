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

#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

void test_genesis_config(const ChainConfig& x) {
    const std::string_view genesis_data{read_genesis_data(x.chain_id)};
    const auto genesis_json{nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false)};
    CHECK_FALSE(genesis_json.is_discarded());

    REQUIRE(genesis_json.contains("config"));
    REQUIRE(genesis_json["config"].is_object());
    const std::optional<ChainConfig> config{ChainConfig::from_json(genesis_json["config"])};
    CHECK(config == x);
}

TEST_CASE("genesis config") {
    std::string_view genesis_data = read_genesis_data(static_cast<uint32_t>(kMainnetConfig.chain_id));
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    auto config = ChainConfig::from_json(genesis_json["config"]);
    REQUIRE(config.has_value());
    CHECK(config.value() == kMainnetConfig);

    genesis_data = read_genesis_data(1'000u);
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK(genesis_json.is_discarded());
}

}  // namespace silkworm
