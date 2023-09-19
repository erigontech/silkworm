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
#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

TEST_CASE("genesis config") {
    std::string genesis_data = read_genesis_data(static_cast<uint32_t>(kMainnetConfig.chain_id));
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    auto config = ChainConfig::from_json(genesis_json["config"]);
    REQUIRE(config.has_value());
    CHECK(config.value() == kMainnetConfig);

    genesis_data = read_genesis_data(static_cast<uint32_t>(kGoerliConfig.chain_id));
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    config = ChainConfig::from_json(genesis_json["config"]);
    REQUIRE(config.has_value());
    CHECK(config.value() == kGoerliConfig);

    genesis_data = read_genesis_data(static_cast<uint32_t>(kSepoliaConfig.chain_id));
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    config = ChainConfig::from_json(genesis_json["config"]);
    REQUIRE(config.has_value());
    CHECK(config.value() == kSepoliaConfig);

    genesis_data = read_genesis_data(1'000u);
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK(genesis_json.is_discarded());
}

nlohmann::json sanity_checked_json(uint64_t chain_id) {
    // Parse genesis data
    std::string genesis_data = read_genesis_data(static_cast<uint32_t>(chain_id));
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK(genesis_json.contains("difficulty"));
    CHECK(genesis_json.contains("nonce"));
    CHECK(genesis_json.contains("gasLimit"));
    CHECK(genesis_json.contains("timestamp"));
    CHECK(genesis_json.contains("extraData"));
    CHECK((genesis_json.contains("alloc") && genesis_json["alloc"].is_object() && !genesis_json["alloc"].empty()));

    return genesis_json;
}

evmc::bytes32 state_root(const nlohmann::json& genesis_json) {
    InMemoryState state;

    for (auto& item : genesis_json["alloc"].items()) {
        REQUIRE((item.value().is_object() && item.value().contains("balance") && item.value()["balance"].is_string()));

        auto address_bytes{from_hex(item.key())};
        REQUIRE((address_bytes != std::nullopt && address_bytes.value().length() == kAddressLength));

        evmc::address account_address = bytes_to_address(*address_bytes);
        auto balance_str{item.value()["balance"].get<std::string>()};
        Account account{0, intx::from_string<intx::uint256>(balance_str)};
        state.update_account(account_address, std::nullopt, account);
    }

    return state.state_root_hash();
}

// https://etherscan.io/block/0
TEST_CASE("mainnet_genesis") {
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
    nlohmann::json genesis_json = sanity_checked_json(kSepoliaConfig.chain_id);
    CHECK(genesis_json["extraData"] == "Sepolia, Athens, Attica, Greece!");

    auto expected_state_root{0x5eb6e371a698b8d68f665192350ffcecbbbf322916f4b51bd79bb6887da3f494_bytes32};
    auto actual_state_root{state_root(genesis_json)};
    CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));

    BlockHeader header{read_genesis_header(genesis_json, actual_state_root)};
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(kSepoliaGenesisHash));
}
}  // namespace silkworm
