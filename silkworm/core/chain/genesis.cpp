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

#include "genesis.hpp"

#include <bit>
#include <cassert>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

extern const char* genesis_mainnet_data();
extern size_t sizeof_genesis_mainnet_data();

extern const char* genesis_goerli_data();
extern size_t sizeof_genesis_goerli_data();

extern const char* genesis_sepolia_data();
extern size_t sizeof_genesis_sepolia_data();

extern const char* genesis_polygon_data();
extern size_t sizeof_genesis_polygon_data();

extern const char* genesis_mumbai_data();
extern size_t sizeof_genesis_mumbai_data();

namespace silkworm {

std::string_view read_genesis_data(ChainId chain_id) {
    switch (chain_id) {
        case kMainnetConfig.chain_id:
            assert(sizeof_genesis_mainnet_data() != 0);
            return {genesis_mainnet_data(), sizeof_genesis_mainnet_data()};
        case kGoerliConfig.chain_id:
            assert(sizeof_genesis_goerli_data() != 0);
            return {genesis_goerli_data(), sizeof_genesis_goerli_data()};
        case kSepoliaConfig.chain_id:
            assert(sizeof_genesis_sepolia_data() != 0);
            return {genesis_sepolia_data(), sizeof_genesis_sepolia_data()};
        case kPolygonConfig.chain_id:
            assert(sizeof_genesis_polygon_data() != 0);
            return {genesis_polygon_data(), sizeof_genesis_polygon_data()};
        case kMumbaiConfig.chain_id:
            assert(sizeof_genesis_mumbai_data() != 0);
            return {genesis_mumbai_data(), sizeof_genesis_mumbai_data()};
        default:
            return "{";  // <- Won't be lately parsed as valid json value
    }
}

BlockHeader read_genesis_header(const nlohmann::json& genesis, const evmc::bytes32& state_root) {
    BlockHeader header;

    if (genesis.contains("extraData")) {
        const std::string extra_data_str{genesis["extraData"].get<std::string>()};
        if (has_hex_prefix(extra_data_str)) {
            const std::optional<Bytes> extra_data_hex{from_hex(extra_data_str)};
            SILKWORM_ASSERT(extra_data_hex.has_value());
            header.extra_data = *extra_data_hex;
        } else {
            header.extra_data = string_view_to_byte_view(extra_data_str);
        }
    }
    if (genesis.contains("mixHash")) {
        const std::optional<Bytes> mix_hash{from_hex(genesis["mixHash"].get<std::string>())};
        SILKWORM_ASSERT(mix_hash.has_value());
        std::memcpy(header.prev_randao.bytes, mix_hash->data(), mix_hash->size());
    }
    if (genesis.contains("nonce")) {
        const uint64_t nonce{std::stoull(genesis["nonce"].get<std::string>(), nullptr, 0)};
        endian::store_big_u64(header.nonce.data(), nonce);
    }
    if (genesis.contains("difficulty")) {
        const auto difficulty_str{genesis["difficulty"].get<std::string>()};
        header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
    }

    header.ommers_hash = kEmptyListHash;
    header.state_root = state_root;
    header.transactions_root = kEmptyRoot;
    header.receipts_root = kEmptyRoot;
    header.gas_limit = std::stoull(genesis["gasLimit"].get<std::string>(), nullptr, 0);
    header.timestamp = std::stoull(genesis["timestamp"].get<std::string>(), nullptr, 0);

    const std::optional<ChainConfig> chain_config{ChainConfig::from_json(genesis["config"])};
    SILKWORM_ASSERT(chain_config.has_value());
    if (chain_config->revision(0, header.timestamp) >= EVMC_LONDON) {
        header.base_fee_per_gas = protocol::kInitialBaseFee;
    }

    return header;
}

InMemoryState read_genesis_allocation(const nlohmann::json& alloc) {
    InMemoryState state;
    for (const auto& item : alloc.items()) {
        const evmc::address address{hex_to_address(item.key())};
        const nlohmann::json& account_json{item.value()};

        Account account;
        account.balance = intx::from_string<intx::uint256>(account_json.at("balance"));
        if (account_json.contains("nonce")) {
            account.nonce = std::stoull(std::string(account_json["nonce"]), nullptr, /*base=*/16);
        }
        if (account_json.contains("code")) {
            const Bytes code{*from_hex(std::string(account_json["code"]))};
            if (!code.empty()) {
                account.incarnation = kDefaultIncarnation;
                account.code_hash = std::bit_cast<evmc_bytes32>(keccak256(code));
                state.update_account_code(address, account.incarnation, account.code_hash, code);
            }
        }
        state.update_account(address, /*initial=*/std::nullopt, account);

        if (account_json.contains("storage")) {
            for (const auto& storage : account_json["storage"].items()) {
                const Bytes key{*from_hex(storage.key())};
                const Bytes value{*from_hex(storage.value().get<std::string>())};
                state.update_storage(address, account.incarnation, to_bytes32(key), /*initial=*/{}, to_bytes32(value));
            }
        }
    }
    return state;
}

}  // namespace silkworm
