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

#include "config.hpp"

#include <vector>

#include <catch2/catch.hpp>

#include <silkworm/core/common/test_util.hpp>

using namespace evmc::literals;

namespace silkworm {

TEST_CASE("Config lookup") {
    CHECK(lookup_known_chain(0u).has_value() == false);
    CHECK(lookup_known_chain(1u)->second == &kMainnetConfig);
    CHECK(lookup_known_chain(kSepoliaConfig.chain_id)->second == &kSepoliaConfig);
    CHECK(lookup_known_chain(12345u).has_value() == false);
    CHECK(lookup_known_chain("mainnet")->second == &kMainnetConfig);
    CHECK(lookup_known_chain("goErli")->second == &kGoerliConfig);
    CHECK(lookup_known_chain("Sepolia")->second == &kSepoliaConfig);
    CHECK(lookup_known_chain("xxxx").has_value() == false);

    auto chains_map{get_known_chains_map()};
    CHECK(chains_map.empty() == false);
    for (auto& [name, id] : chains_map) {
        REQUIRE(lookup_known_chain(name).has_value());
        REQUIRE(lookup_known_chain(id).has_value());
        REQUIRE(lookup_known_chain(name) == lookup_known_chain(id));
        REQUIRE(lookup_known_chain(name)->second->chain_id == id);
    }
}

TEST_CASE("Config revision") {
    CHECK(kMainnetConfig.revision(0, 0) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1, 1438269988) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(200'000, 1441661589) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1'000'000, 1455404053) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1'149'999, 1457981342) == EVMC_FRONTIER);
    CHECK(kMainnetConfig.revision(1'150'000, 1457981393) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(1'150'001, 1457981402) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(1'920'000, 1469020840) == EVMC_HOMESTEAD);  // DAO fork doesn't have an evmc_revision
    CHECK(kMainnetConfig.revision(2'000'000, 1470173578) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(2'462'999, 1476796747) == EVMC_HOMESTEAD);
    CHECK(kMainnetConfig.revision(2'463'000, 1476796771) == EVMC_TANGERINE_WHISTLE);
    CHECK(kMainnetConfig.revision(2'463'001, 1476796812) == EVMC_TANGERINE_WHISTLE);
    CHECK(kMainnetConfig.revision(2'674'999, 1479831337) == EVMC_TANGERINE_WHISTLE);
    CHECK(kMainnetConfig.revision(2'675'000, 1479831344) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(2'675'001, 1479831347) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(3'000'000, 1484475035) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(4'000'000, 1499633567) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(4'369'999, 1508131303) == EVMC_SPURIOUS_DRAGON);
    CHECK(kMainnetConfig.revision(4'370'000, 1508131331) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(4'370'001, 1508131362) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(5'000'000, 1517319693) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(6'000'000, 1532118564) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(7'000'000, 1546466952) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(7'279'999, 1551383501) == EVMC_BYZANTIUM);
    CHECK(kMainnetConfig.revision(7'280'000, 1551383524) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(7'280'001, 1551383544) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(8'000'000, 1561100149) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(9'000'000, 1574706444) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(9'068'999, 1575764708) == EVMC_PETERSBURG);
    CHECK(kMainnetConfig.revision(9'069'000, 1575764709) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(9'069'001, 1575764711) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(9'200'000, 1577953849) == EVMC_ISTANBUL);  // Muir Glacier doesn't have an evmc_revision
    CHECK(kMainnetConfig.revision(10'000'000, 1588598533) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(11'000'000, 1601957824) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(12'000'000, 1615234816) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(12'243'999, 1618481214) == EVMC_ISTANBUL);
    CHECK(kMainnetConfig.revision(12'244'000, 1618481223) == EVMC_BERLIN);
    CHECK(kMainnetConfig.revision(12'244'001, 1618481230) == EVMC_BERLIN);
    CHECK(kMainnetConfig.revision(12'964'999, 1628166812) == EVMC_BERLIN);
    CHECK(kMainnetConfig.revision(12'965'000, 1628166822) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(12'965'001, 1628166835) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(13'000'000, 1628632419) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(13'773'000, 1639079723) == EVMC_LONDON);  // Arrow Glacier doesn't have an evmc_revision
    CHECK(kMainnetConfig.revision(14'000'000, 1642114795) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(15'000'000, 1655778535) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(15'050'000, 1656586444) == EVMC_LONDON);  // Gray Glacier doesn't have an evmc_revision
    CHECK(kMainnetConfig.revision(15'537'393, 1663224162) == EVMC_LONDON);  // We still use EVMC_LONDON for The Merge, though formally it should be EVMC_PARIS
    CHECK(kMainnetConfig.revision(16'000'000, 1668811907) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(17'000'000, 1680911891) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(17'034'869, 1681338443) == EVMC_LONDON);
    CHECK(kMainnetConfig.revision(17'034'870, 1681338479) == EVMC_SHANGHAI);
    CHECK(kMainnetConfig.revision(17'034'871, 1681338503) == EVMC_SHANGHAI);
    CHECK(kMainnetConfig.revision(100'000'000, 3000000000) == EVMC_SHANGHAI);

    CHECK(test::kLondonConfig.revision(0, 0) == EVMC_LONDON);
    CHECK(test::kShanghaiConfig.revision(0, 0) == EVMC_SHANGHAI);
}

// For Polygon the Agra hard fork (=Shanghai without withdrawals) is activated based on the block number
// rather than timestamp.
TEST_CASE("Agra revision") {
    CHECK(kMumbaiConfig.revision(41'874'000 - 1, 0) == EVMC_LONDON);
    CHECK(kMumbaiConfig.revision(41'874'000, 0) == EVMC_SHANGHAI);
    CHECK(kMumbaiConfig.revision(41'874'000 + 1, 0) == EVMC_SHANGHAI);
}

TEST_CASE("distinct_fork_points") {
    const std::vector<BlockNum> kExpectedMainnetForkNumbers{
        1'150'000,
        1'920'000,
        2'463'000,
        2'675'000,
        4'370'000,
        7'280'000,
        9'069'000,
        9'200'000,
        12'244'000,
        12'965'000,
        13'773'000,
        15'050'000,
    };
    const std::vector<BlockNum> kExpectedMainnetForkTimes{
        1'681'338'455,
    };
    std::vector<uint64_t> kExpectedMainnetForkPoints{kExpectedMainnetForkNumbers};
    kExpectedMainnetForkPoints.insert(kExpectedMainnetForkPoints.end(),
                                      kExpectedMainnetForkTimes.cbegin(), kExpectedMainnetForkTimes.cend());

    CHECK(kMainnetConfig.distinct_fork_numbers() == kExpectedMainnetForkNumbers);
    CHECK(kMainnetConfig.distinct_fork_times() == kExpectedMainnetForkTimes);
    CHECK(kMainnetConfig.distinct_fork_points() == kExpectedMainnetForkPoints);

    const std::vector<BlockNum> kExpectedGoerliForkNumbers{
        1'561'651,
        4'460'644,
        5'062'605,
    };
    const std::vector<BlockNum> kExpectedGoerliForkTimes{
        1'678'832'736,
    };
    std::vector<uint64_t> kExpectedGoerliForkPoints{kExpectedGoerliForkNumbers};
    kExpectedGoerliForkPoints.insert(kExpectedGoerliForkPoints.end(),
                                     kExpectedGoerliForkTimes.cbegin(), kExpectedGoerliForkTimes.cend());

    CHECK(kGoerliConfig.distinct_fork_numbers() == kExpectedGoerliForkNumbers);
    CHECK(kGoerliConfig.distinct_fork_times() == kExpectedGoerliForkTimes);
    CHECK(kGoerliConfig.distinct_fork_points() == kExpectedGoerliForkPoints);
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
            "grayGlacierBlock":15050000,
            "terminalTotalDifficulty":"58750000000000000000000",
            "shanghaiTime":1681338455,
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
            "mergeNetsplitBlock":10000
        })");

    const std::optional<ChainConfig> config2{ChainConfig::from_json(merge_test_json)};

    REQUIRE(config2);
    CHECK(config2->terminal_total_difficulty == intx::from_string<intx::uint256>("39387012740608862000000"));
    CHECK(config2->merge_netsplit_block == 10000);

    CHECK(config2->to_json() == merge_test_json);
}

TEST_CASE("terminalTotalDifficulty as JSON number (Erigon compatibility)") {
    const auto mainnet_json_ttd_number = nlohmann::json::parse(R"({
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
            "grayGlacierBlock":15050000,
            "terminalTotalDifficulty":58750000000000000000000,
            "shanghaiTime":1681338455,
            "ethash":{}
        })");

    const std::optional<ChainConfig> config1{ChainConfig::from_json(mainnet_json_ttd_number)};

    REQUIRE(config1);
    CHECK(config1 == kMainnetConfig);
    CHECK(config1->to_json() != mainnet_json_ttd_number);  // "58750000000000000000000" vs 5.875e+22
    CHECK(config1->terminal_total_difficulty == intx::from_string<intx::uint256>("58750000000000000000000"));

    const auto goerli_json_ttd_number = nlohmann::json::parse(R"({
            "chainId":5,
            "homesteadBlock":0,
            "eip150Block":0,
            "eip155Block":0,
            "byzantiumBlock":0,
            "constantinopleBlock":0,
            "petersburgBlock":0,
            "istanbulBlock":1561651,
            "berlinBlock":4460644,
            "londonBlock":5062605,
            "terminalTotalDifficulty":10790000,
            "shanghaiTime":1678832736,
            "clique":{}
        })");

    const std::optional<ChainConfig> config2{ChainConfig::from_json(goerli_json_ttd_number)};

    REQUIRE(config2);
    CHECK(config2 == kGoerliConfig);
    CHECK(config2->to_json() != goerli_json_ttd_number);  // "10790000" vs 10790000
    CHECK(config2->terminal_total_difficulty == intx::from_string<intx::uint256>("10790000"));

    const auto sepolia_json_ttd_number = nlohmann::json::parse(R"({
            "chainId":11155111,
            "homesteadBlock":0,
            "eip150Block":0,
            "eip155Block":0,
            "byzantiumBlock":0,
            "constantinopleBlock":0,
            "petersburgBlock":0,
            "istanbulBlock":0,
            "muirGlacierBlock":0,
            "berlinBlock":0,
            "londonBlock":0,
            "terminalTotalDifficulty":17000000000000000,
            "mergeNetsplitBlock":1735371,
            "shanghaiTime":1677557088,
            "ethash":{}
        })");

    const std::optional<ChainConfig> config3{ChainConfig::from_json(sepolia_json_ttd_number)};

    REQUIRE(config3);
    CHECK(config3 == kSepoliaConfig);
    CHECK(config3->to_json() != sepolia_json_ttd_number);  // "17000000000000000" vs 17000000000000000
    CHECK(config3->terminal_total_difficulty == intx::from_string<intx::uint256>("17000000000000000"));
}

}  // namespace silkworm
