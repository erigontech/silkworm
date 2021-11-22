
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

#include "genesis.hpp"

#include <catch2/catch.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/util.hpp>
#include <silkworm/state/in_memory_state.hpp>

#include "config.hpp"
#include "identity.hpp"

namespace silkworm {

TEST_CASE("genesis config") {
    std::string genesis_data = read_genesis_data(static_cast<uint32_t>(kMainnetConfig.chain_id));
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    auto config = ChainConfig::from_json(genesis_json["config"]);
    CHECK(config.has_value());
    CHECK(config.value() == kMainnetConfig);

    genesis_data = read_genesis_data(static_cast<uint32_t>(kGoerliConfig.chain_id));
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    config = ChainConfig::from_json(genesis_json["config"]);
    CHECK(config.has_value());
    CHECK(config.value() == kGoerliConfig);

    genesis_data = read_genesis_data(static_cast<uint32_t>(kRinkebyConfig.chain_id));
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK((genesis_json.contains("config") && genesis_json["config"].is_object()));
    config = ChainConfig::from_json(genesis_json["config"]);
    CHECK(config.has_value());
    CHECK(config.value() == kRinkebyConfig);

    genesis_data = read_genesis_data(1'000u);
    genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK(genesis_json.is_discarded());
}

TEST_CASE("mainnet_genesis") {
    // Parse genesis data
    std::string genesis_data = read_genesis_data(static_cast<uint32_t>(kMainnetConfig.chain_id));
    nlohmann::json genesis_json = nlohmann::json::parse(genesis_data, nullptr, /* allow_exceptions = */ false);
    CHECK_FALSE(genesis_json.is_discarded());

    CHECK(genesis_json.contains("difficulty"));
    CHECK(genesis_json.contains("nonce"));
    CHECK(genesis_json.contains("gasLimit"));
    CHECK(genesis_json.contains("timestamp"));
    CHECK(genesis_json.contains("extraData"));
    CHECK((genesis_json.contains("alloc") && genesis_json["alloc"].is_object() && !genesis_json["alloc"].empty()));

    InMemoryState state;

    for (auto& item : genesis_json["alloc"].items()) {
        REQUIRE((item.value().is_object() && item.value().contains("balance") && item.value()["balance"].is_string()));

        auto address_bytes{from_hex(item.key())};
        REQUIRE((address_bytes != std::nullopt && address_bytes.value().length() == kAddressLength));

        evmc::address account_address = silkworm::to_evmc_address(*address_bytes);
        auto balance_str{item.value()["balance"].get<std::string>()};
        Account account{0, intx::from_string<intx::uint256>(balance_str)};
        state.update_account(account_address, std::nullopt, account);
    }

    SECTION("state_root") {
        auto expected_state_root{0xd7f8974fb5ac78d9ac099b9ad5018bedc2ce0a72dad1827a1709da30580f0544_bytes32};
        auto actual_state_root{state.state_root_hash()};
        CHECK(to_hex(expected_state_root) == to_hex(actual_state_root));
    }

    // Fill Header
    BlockHeader header;
    auto parent_hash{from_hex(genesis_json["parentHash"].get<std::string>())};
    if (parent_hash.has_value()) {
        header.parent_hash = to_bytes32(*parent_hash);
    }
    header.ommers_hash = kEmptyListHash;
    header.beneficiary = 0x0000000000000000000000000000000000000000_address;
    header.state_root = state.state_root_hash();
    header.transactions_root = kEmptyRoot;
    header.receipts_root = kEmptyRoot;
    auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
    header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
    header.number = 0;
    header.gas_limit = std::stoull(genesis_json["gasLimit"].get<std::string>(), nullptr, 0);
    header.timestamp = std::stoull(genesis_json["timestamp"].get<std::string>(), nullptr, 0);

    auto extra_data = from_hex(genesis_json["extraData"].get<std::string>());
    if (extra_data.has_value()) {
        header.extra_data = *extra_data;
    }

    auto mix_data = from_hex(genesis_json["mixhash"].get<std::string>());
    CHECK((mix_data.has_value() && mix_data->size() == kHashLength));
    header.mix_hash = to_bytes32(*mix_data);

    auto nonce = std::stoull(genesis_json["nonce"].get<std::string>(), nullptr, 0);
    endian::store_big_u64(header.nonce.data(), nonce);

    // Verify our RLP encoding produces the same result
    auto computed_hash{header.hash()};
    CHECK(to_hex(computed_hash) == to_hex(ChainIdentity::mainnet.genesis_hash));

    // TODO (Andrea) Why this fails for genesis ?
    // auto seal_hash(header.hash(/*for_sealing =*/true));
    // ethash::hash256 sealh256{};
    // std::memcpy(sealh256.bytes, seal_hash.bytes, 32);
    // auto boundary{ethash::get_boundary_from_diff(header.difficulty)};
    // auto epoch_context{ethash::create_epoch_context(0)};
    // auto result{ethash::hash(*epoch_context, sealh256, nonce)};
    // CHECK(ethash::is_less_or_equal(result.final_hash, boundary));
}

}  // namespace silkworm
