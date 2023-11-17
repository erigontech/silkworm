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
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

void test_genesis_config(const ChainConfig& x) {
    const std::string_view genesis_data{read_genesis_data(x.chain_id)};
    const nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    REQUIRE(genesis_json.contains("config"));
    REQUIRE(genesis_json["config"].is_object());
    const std::optional<ChainConfig> config{ChainConfig::from_json(genesis_json["config"])};
    CHECK(config == x);
}

TEST_CASE("unknown genesis") {
    const std::string_view genesis_data{read_genesis_data(1'000u)};
    const nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK(genesis_json.is_discarded());
}

nlohmann::json sanity_checked_json(uint64_t chain_id) {
    // Parse genesis data
    std::string_view genesis_data{read_genesis_data(static_cast<uint32_t>(chain_id))};
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK(genesis_json.contains("difficulty"));
    CHECK(genesis_json.contains("gasLimit"));
    CHECK(genesis_json.contains("timestamp"));
    CHECK((genesis_json.contains("alloc") && genesis_json["alloc"].is_object() && !genesis_json["alloc"].empty()));

    return genesis_json;
}

evmc::bytes32 state_root(const nlohmann::json& genesis_json) {
    InMemoryState state{read_genesis_allocation(genesis_json["alloc"])};
    return state.state_root_hash();
}

// https://etherscan.io/block/0
TEST_CASE("mainnet_genesis") {
    test_genesis_config(kMainnetConfig);
    nlohmann::json genesis_json = sanity_checked_json(kMainnetConfig.chain_id);

    auto expected_state_root{0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544_bytes32};
    auto actual_state_root{state_root(genesis_json)};
    CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));

    BlockHeader header{read_genesis_header(genesis_json, actual_state_root)};

    // Verify our RLP encoding produces the same result
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(kMainnetGenesisHash));

    // TODO (Andrea) Why this fails for genesis ?
    // auto seal_hash(header.hash(/*for_sealing =*/true));
    // ethash::hash256 sealh256{};
    // std::memcpy(sealh256.bytes, seal_hash.bytes, 32);
    // auto boundary{ethash::get_boundary_from_diff(header.difficulty)};
    // auto epoch_context{ethash::create_epoch_context(0)};
    // auto result{ethash::hash(*epoch_context, sealh256, nonce)};
    // CHECK(ethash::is_less_or_equal(result.final_hash, boundary));
}

// https://goerli.etherscan.io/block/0
TEST_CASE("Goerli genesis") {
    test_genesis_config(kGoerliConfig);
    nlohmann::json genesis_json = sanity_checked_json(kGoerliConfig.chain_id);

    auto expected_state_root{0x5d6cded585e73c4e322c30c2f782a336316f17dd85a4863b9d838d2d4b8b3008_bytes32};
    auto actual_state_root{state_root(genesis_json)};
    CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));

    BlockHeader header{read_genesis_header(genesis_json, actual_state_root)};
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(kGoerliGenesisHash));
}

// https://sepolia.etherscan.io/block/0
TEST_CASE("Sepolia genesis") {
    test_genesis_config(kSepoliaConfig);
    nlohmann::json genesis_json = sanity_checked_json(kSepoliaConfig.chain_id);
    CHECK(genesis_json["extraData"] == "Sepolia, Athens, Attica, Greece!");

    auto expected_state_root{0x5eb6e371a698b8d68f665192350ffcecbbbf322916f4b51bd79bb6887da3f494_bytes32};
    auto actual_state_root{state_root(genesis_json)};
    CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));

    BlockHeader header{read_genesis_header(genesis_json, actual_state_root)};
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(kSepoliaGenesisHash));
}

TEST_CASE("Polygon genesis") {
    test_genesis_config(kPolygonConfig);
    nlohmann::json genesis_json = sanity_checked_json(kPolygonConfig.chain_id);

    auto expected_state_root{0x654f28d19b44239d1012f27038f1f71b3d4465dc415a382fb2b7009cba1527c8_bytes32};
    auto actual_state_root{state_root(genesis_json)};
    CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));

    BlockHeader header{read_genesis_header(genesis_json, actual_state_root)};
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(kPolygonGenesisHash));
}

TEST_CASE("Mumbai genesis") {
    test_genesis_config(kMumbaiConfig);
    nlohmann::json genesis_json = sanity_checked_json(kMumbaiConfig.chain_id);

    auto expected_state_root{0x1784d1c465e9a4c39cc58b1df8d42f2669b00b1badd231a7c4679378b9d91330_bytes32};
    auto actual_state_root{state_root(genesis_json)};
    CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));

    BlockHeader header{read_genesis_header(genesis_json, actual_state_root)};
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(kMumbaiGenesisHash));
}

}  // namespace silkworm
