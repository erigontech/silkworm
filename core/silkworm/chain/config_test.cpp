/*
   Copyright 2021 The Silkworm Authors

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

#include "config.hpp"

#include <catch2/catch.hpp>

using namespace evmc::literals;

namespace silkworm {

TEST_CASE("Config lookup") {
    CHECK(lookup_chain_config(0u) == nullptr);
    CHECK(lookup_chain_config(1u) == &kMainnetConfig);
    CHECK(lookup_chain_config(3u) == &kRopstenConfig);
    CHECK(lookup_chain_config(4u) == &kRinkebyConfig);
    CHECK(lookup_chain_config(5u) == &kGoerliConfig);
    CHECK(lookup_chain_config(12345u) == nullptr);
    CHECK(lookup_chain_config("mainnet") == &kMainnetConfig);
    CHECK(lookup_chain_config("ropsten") == &kRopstenConfig);
    CHECK(lookup_chain_config("Rinkeby") == &kRinkebyConfig);
    CHECK(lookup_chain_config("goErli") == &kGoerliConfig);
    CHECK(lookup_chain_config("xxxx") == nullptr);

    auto chains_map{get_known_chains_map()};
    CHECK(chains_map.empty() == false);
    for (auto& [name, id] : chains_map) {
        REQUIRE(lookup_chain_config(name) != nullptr);
        REQUIRE(lookup_chain_config(id) != nullptr);
        REQUIRE(lookup_chain_config(name) == lookup_chain_config(id));
        REQUIRE(lookup_chain_config(name)->chain_id == id);
    }
}

TEST_CASE("Config revision") {
    CHECK(kMainnetConfig.revision_block(EVMC_FRONTIER) == 0);
    CHECK(kMainnetConfig.revision_block(EVMC_HOMESTEAD) == 1'150'000);
    CHECK(kMainnetConfig.revision_block(EVMC_TANGERINE_WHISTLE) == 2'463'000);
    CHECK(kMainnetConfig.revision_block(EVMC_SPURIOUS_DRAGON) == 2'675'000);
    CHECK(kMainnetConfig.revision_block(EVMC_BYZANTIUM) == 4'370'000);
    CHECK(kMainnetConfig.revision_block(EVMC_CONSTANTINOPLE) == 7'280'000);
    CHECK(kMainnetConfig.revision_block(EVMC_PETERSBURG) == 7'280'000);
    CHECK(kMainnetConfig.revision_block(EVMC_ISTANBUL) == 9'069'000);
    CHECK(kMainnetConfig.revision_block(EVMC_BERLIN) == 12'244'000);
    CHECK(kMainnetConfig.revision_block(EVMC_LONDON) == 12'965'000);
    CHECK(kMainnetConfig.revision_block(EVMC_SHANGHAI) == std::nullopt);

    CHECK(kMainnetConfig.revision(0) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(200'000) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1'000'000) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1'149'999) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1'150'000) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(1'150'001) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(2'000'000) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(2'462'999) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(2'463'000) == EVMC_TANGERINE_WHISTLE);
    CHECK(kMainnetConfig.revision(2'463'001) == EVMC_TANGERINE_WHISTLE);
    CHECK(kMainnetConfig.revision(2'674'999) == EVMC_TANGERINE_WHISTLE);
    CHECK(kMainnetConfig.revision(2'675'000) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(2'675'001) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(3'000'000) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(4'000'000) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(4'369'999) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(4'370'000) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(4'370'001) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(5'000'000) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(6'000'000) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(7'000'000) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(7'279'999) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(7'280'000) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(7'280'001) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(8'000'000) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(9'000'000) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(9'068'999) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(9'069'000) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(9'069'001) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(9'200'000) == EVMC_ISTANBUL);  // Muir Glacier doesn't have an evmc_revision
    CHECK(kMainnetConfig.revision(10'000'000) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(11'000'000) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(12'000'000) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(12'243'999) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(12'244'000) == EVMC_BERLIN);
    CHECK(kMainnetConfig.revision(12'244'001) == EVMC_BERLIN);
    CHECK(kMainnetConfig.revision(12'964'999) == EVMC_BERLIN);
    CHECK(kMainnetConfig.revision(12'965'000) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(12'965'001) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(13'000'000) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(13'773'000) == EVMC_LONDON);  // Arrow Glacier doesn't have an evmc_revision
    CHECK(kMainnetConfig.revision(14'000'000) == EVMC_LONDON);
}

TEST_CASE("JSON serialization") {
    const auto unrelated_json = nlohmann::json::parse(R"({
            "firstName": "John",
            "lastName": "Smith",
            "children": [],
            "spouse": null
        })");

    CHECK(!ChainConfig::from_json(unrelated_json));

    const auto mainnet_json = nlohmann::json::parse(R"({
            "chainId":1,
            "homesteadBlock":1150000,
            "daoForkBlock":1920000,
            "eip150Block":2463000,
            "eip155Block":2675000,
            "byzantiumBlock":4370000,
            "constantinopleBlock":7280000,
            "petersburgBlock":7280000,
            "istanbulBlock":9069000,
            "muirGlacierBlock":9200000,
            "berlinBlock":12244000,
            "londonBlock":12965000,
            "arrowGlacierBlock":13773000,
            "ethash":{}
        })");

    const std::optional<ChainConfig> config1{ChainConfig::from_json(mainnet_json)};

    REQUIRE(config1);
    CHECK(config1 == kMainnetConfig);
    CHECK(config1->to_json() == mainnet_json);

    const auto merge_test_json = nlohmann::json::parse(R"({
            "chainId":1337302,
            "homesteadBlock":0,
            "eip150Block":0,
            "eip155Block":0,
            "byzantiumBlock":0,
            "constantinopleBlock":0,
            "petersburgBlock":0,
            "istanbulBlock":0,
            "berlinBlock":0,
            "londonBlock":0,
            "terminalTotalDifficulty":"39387012740608862000000",
            "terminalBlockNumber": 10000,
            "terminalBlockHash": "0x6dc57fd586f41ee340124c3a005642af7731a9ca7a7b70d989a7e2833e4ab740"
        })");

    const std::optional<ChainConfig> config2{ChainConfig::from_json(merge_test_json)};

    REQUIRE(config2);
    CHECK(config2->terminal_total_difficulty == intx::from_string<intx::uint256>("39387012740608862000000"));
    CHECK(config2->terminal_block_number == 10000);
    CHECK(config2->terminal_block_hash == 0x6dc57fd586f41ee340124c3a005642af7731a9ca7a7b70d989a7e2833e4ab740_bytes32);

    CHECK(config2->to_json() == merge_test_json);
}

}  // namespace silkworm
