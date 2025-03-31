// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "genesis.hpp"

#include <bit>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/chain/genesis_amoy.hpp>
#include <silkworm/core/chain/genesis_bor_mainnet.hpp>
#include <silkworm/core/chain/genesis_holesky.hpp>
#include <silkworm/core/chain/genesis_mainnet.hpp>
#include <silkworm/core/chain/genesis_sepolia.hpp>
#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

namespace silkworm {

std::string_view read_genesis_data(ChainId chain_id) {
    switch (chain_id) {
        case *kKnownChainNameToId.find("mainnet"sv):
            return kGenesisMainnetJson;
        case *kKnownChainNameToId.find("holesky"sv):
            return kGenesisHoleskyJson;
        case *kKnownChainNameToId.find("sepolia"sv):
            return kGenesisSepoliaJson;
        case *kKnownChainNameToId.find("bor-mainnet"sv):
            return kGenesisBorMainnetJson;
        case *kKnownChainNameToId.find("amoy"sv):
            return kGenesisAmoyJson;
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
            account.nonce = std::stoull(account_json["nonce"].get<std::string>(), nullptr, /*base=*/16);
        }
        if (account_json.contains("code")) {
            const Bytes code{*from_hex(account_json["code"].get<std::string>())};
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
