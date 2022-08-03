/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <cassert>
#include <stdexcept>

#include <silkworm/common/assert.hpp>
#include <silkworm/common/cast.hpp>

#include "config.hpp"
#include "protocol_param.hpp"

extern const char* genesis_mainnet_data();
extern size_t sizeof_genesis_mainnet_data();

extern const char* genesis_goerli_data();
extern size_t sizeof_genesis_goerli_data();

extern const char* genesis_ropsten_data();
extern size_t sizeof_genesis_ropsten_data();

extern const char* genesis_rinkeby_data();
extern size_t sizeof_genesis_rinkeby_data();

extern const char* genesis_sepolia_data();
extern size_t sizeof_genesis_sepolia_data();

namespace silkworm {

std::string read_genesis_data(uint64_t chain_id) {
    switch (chain_id) {
        case kMainnetConfig.chain_id:
            assert(sizeof_genesis_mainnet_data() != 0);
            return std::string(genesis_mainnet_data(), sizeof_genesis_mainnet_data());
        case kRopstenConfig.chain_id:
            assert(sizeof_genesis_ropsten_data() != 0);
            return std::string(genesis_ropsten_data(), sizeof_genesis_ropsten_data());
        case kRinkebyConfig.chain_id:
            assert(sizeof_genesis_rinkeby_data() != 0);
            return std::string(genesis_rinkeby_data(), sizeof_genesis_rinkeby_data());
        case kGoerliConfig.chain_id:
            assert(sizeof_genesis_goerli_data() != 0);
            return std::string(genesis_goerli_data(), sizeof_genesis_goerli_data());
        case kSepoliaConfig.chain_id:
            assert(sizeof_genesis_sepolia_data() != 0);
            return std::string(genesis_sepolia_data(), sizeof_genesis_sepolia_data());
        default:
            return "{";  // <- Won't be lately parsed as valid json value
    }
}

BlockHeader read_genesis_header(const nlohmann::json& genesis_json, const evmc::bytes32& state_root) {
    BlockHeader header;

    if (genesis_json.contains("extraData")) {
        const std::string extra_data_str{genesis_json["extraData"].get<std::string>()};
        if (has_hex_prefix(extra_data_str)) {
            const std::optional<Bytes> extra_data_hex{from_hex(extra_data_str)};
            SILKWORM_ASSERT(extra_data_hex.has_value());
            header.extra_data = *extra_data_hex;
        } else {
            header.extra_data = string_view_to_byte_view(extra_data_str);
        }
    }
    if (genesis_json.contains("mixHash")) {
        const std::optional<Bytes> mix_hash{from_hex(genesis_json["mixHash"].get<std::string>())};
        SILKWORM_ASSERT(mix_hash.has_value());
        std::memcpy(header.mix_hash.bytes, mix_hash->data(), mix_hash->size());
    }
    if (genesis_json.contains("nonce")) {
        const uint64_t nonce{std::stoull(genesis_json["nonce"].get<std::string>(), nullptr, 0)};
        endian::store_big_u64(header.nonce.data(), nonce);
    }
    if (genesis_json.contains("difficulty")) {
        const auto difficulty_str{genesis_json["difficulty"].get<std::string>()};
        header.difficulty = intx::from_string<intx::uint256>(difficulty_str);
    }

    header.ommers_hash = kEmptyListHash;
    header.state_root = state_root;
    header.transactions_root = kEmptyRoot;
    header.receipts_root = kEmptyRoot;
    header.gas_limit = std::stoull(genesis_json["gasLimit"].get<std::string>(), nullptr, 0);
    header.timestamp = std::stoull(genesis_json["timestamp"].get<std::string>(), nullptr, 0);

    const std::optional<ChainConfig> chain_config{ChainConfig::from_json(genesis_json["config"])};
    SILKWORM_ASSERT(chain_config.has_value());
    if (chain_config->revision(0) >= EVMC_LONDON) {
        header.base_fee_per_gas = param::kInitialBaseFee;
    }

    return header;
}

}  // namespace silkworm
