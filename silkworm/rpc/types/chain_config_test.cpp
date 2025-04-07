// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "chain_config.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::rpc {

/*TEST_CASE("create empty chain config", "[rpc][types][chain_config]") {
    ChainConfig chain_config{};
    CHECK(chain_config.genesis_hash == evmc::bytes32{});
    CHECK(chain_config.config == R"(null)"_json);
}

TEST_CASE("print empty chain config", "[rpc][types][chain_config]") {
    ChainConfig chain_config{};
    CHECK_NOTHROW(silkworm::test_util::null_stream() << chain_config);
}

TEST_CASE("cannot create forks from empty chain config", "[rpc][types][chain_config]") {
    ChainConfig chain_config{};
    CHECK_THROWS_AS(Forks{chain_config}, std::system_error);
}

TEST_CASE("create forks from chain config", "[rpc][types][chain_config]") {
    ChainConfig chain_config{
        0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32,
        R"({
            "berlinBlock":12244000,
            "byzantiumBlock":4370000,
            "chainId":1,
            "constantinopleBlock":7280000,
            "daoForkBlock":1920000,
            "eip150Block":2463000,
            "eip155Block":2675000,
            "ethash":{},
            "homesteadBlock":1150000,
            "istanbulBlock":9069000,
            "londonBlock":12965000,
            "muirGlacierBlock":9200000,
            "petersburgBlock":7280000
        })"_json};
    Forks forks{chain_config};
    CHECK(forks.genesis_hash == 0xd4e56740f876aef8c010b86a40d5f56745a118d0906a34e69aec8c0db1cb8fa3_bytes32);
    CHECK(forks.block_nums[0] == 1'150'000);
    CHECK(forks.block_nums[1] == 1'920'000);
    CHECK(forks.block_nums[2] == 2'463'000);
    CHECK(forks.block_nums[3] == 2'675'000);
    CHECK(forks.block_nums[4] == 4'370'000);
    CHECK(forks.block_nums[5] == 7'280'000);
    CHECK(forks.block_nums[6] == 9'069'000);
    CHECK(forks.block_nums[7] == 9'200'000);
    CHECK(forks.block_nums[8] == 12'244'000);
    CHECK(forks.block_nums[9] == 12'965'000);
}*/

}  // namespace silkworm::rpc
