// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "config.hpp"

#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/test_util.hpp>

using namespace evmc::literals;

namespace silkworm {

TEST_CASE("Known configs") {
    static_assert(kKnownChainConfigs.size() == kKnownChainNameToId.size());
    for (const auto& [_, id] : kKnownChainNameToId) {
        const auto config{kKnownChainConfigs.find(id)};
        REQUIRE(config);
        CHECK((*config)->chain_id == id);
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
    CHECK(kMainnetConfig.revision(19'428'734, 1710338123) == EVMC_SHANGHAI);
    CHECK(kMainnetConfig.revision(19'428'735, 1710338135) == EVMC_CANCUN);
    CHECK(kMainnetConfig.revision(20'000'000, 1800000000) == EVMC_CANCUN);

    CHECK(test::kLondonConfig.revision(0, 0) == EVMC_LONDON);
    CHECK(test::kShanghaiConfig.revision(0, 0) == EVMC_SHANGHAI);
}

// For Polygon the Agra hard fork (=Shanghai without withdrawals) is activated based on the block number
// rather than timestamp.
TEST_CASE("Agra revision") {
    auto bor_config{std::get<protocol::bor::Config>(kBorMainnetConfig.rule_set_config)};
    CHECK(kBorMainnetConfig.revision(bor_config.agra_block - 1, 0) == EVMC_LONDON);
    CHECK(kBorMainnetConfig.revision(bor_config.agra_block, 0) == EVMC_SHANGHAI);
    CHECK(kBorMainnetConfig.revision(bor_config.agra_block + 1, 0) == EVMC_SHANGHAI);
}

TEST_CASE("distinct_fork_points") {
    const std::vector<BlockNum> expected_mainnet_fork_numbers{
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
    const std::vector<BlockTime> expected_mainnet_fork_times{
        1681338455,
        1710338135,
    };
    std::vector<uint64_t> expected_mainnet_fork_points{expected_mainnet_fork_numbers};
    expected_mainnet_fork_points.insert(expected_mainnet_fork_points.end(),
                                        expected_mainnet_fork_times.cbegin(), expected_mainnet_fork_times.cend());

    CHECK(kMainnetConfig.distinct_fork_block_nums() == expected_mainnet_fork_numbers);
    CHECK(kMainnetConfig.distinct_fork_times() == expected_mainnet_fork_times);
    CHECK(kMainnetConfig.distinct_fork_points() == expected_mainnet_fork_points);
}

TEST_CASE("JSON serialization") {
    const auto unrelated_json = nlohmann::json::parse(R"({
            "firstName": "John",
            "lastName": "Smith",
            "children": [],
            "spouse": null
        })");

    CHECK(!ChainConfig::from_json(unrelated_json));

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
            "mergeNetsplitBlock":10000,
            "terminalTotalDifficulty":"0"
        })");

    const std::optional<ChainConfig> config{ChainConfig::from_json(merge_test_json)};

    REQUIRE(config);
    CHECK(config->terminal_total_difficulty == intx::from_string<intx::uint256>("0"));
    CHECK(config->merge_netsplit_block == 10000);

    CHECK(config->to_json() == merge_test_json);
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
    CHECK(config1->to_json() != mainnet_json_ttd_number);  // "58750000000000000000000" vs 5.875e+22
    CHECK(config1->terminal_total_difficulty == intx::from_string<intx::uint256>("58750000000000000000000"));

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

    const std::optional<ChainConfig> config2{ChainConfig::from_json(sepolia_json_ttd_number)};

    REQUIRE(config2);
    CHECK(config2->to_json() != sepolia_json_ttd_number);  // "17000000000000000" vs 17000000000000000
    CHECK(config2->terminal_total_difficulty == intx::from_string<intx::uint256>("17000000000000000"));
}

}  // namespace silkworm
