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

namespace silkworm {

TEST_CASE("Config lookup") {
    CHECK(lookup_chain_config(0) == nullptr);
    CHECK(lookup_chain_config(1) == &kMainnetConfig);
    CHECK(lookup_chain_config(3) == &kRopstenConfig);
    CHECK(lookup_chain_config(4) == &kRinkebyConfig);
    CHECK(lookup_chain_config(5) == &kGoerliConfig);
    CHECK(lookup_chain_config(12345) == nullptr);
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
            "ethash":{}
        })");

    const std::optional<ChainConfig> config{ChainConfig::from_json(mainnet_json)};

    REQUIRE(config);
    CHECK(config == kMainnetConfig);
    CHECK(config->to_json() == mainnet_json);
}

}  // namespace silkworm
