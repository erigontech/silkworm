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

#include <functional>
#include <set>

// Disable warning to overcome bug in GCC 12: https://gcc.gnu.org/bugzilla/show_bug.cgi?id=104336
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wrestrict"
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#pragma GCC diagnostic pop

#include <silkworm/common/as_range.hpp>

//! Function definition required by BOOST_NO_EXCEPTIONS which in turn is defined because of -fno-exceptions
//! \details neither throwing nor returning are valid here so aborting is pretty much the only solution
void boost::throw_exception(std::exception const& /*e*/) {
    std::abort();
}

//! Function definition required by BOOST_NO_EXCEPTIONS which in turn is defined because of -fno-exceptions
//! \details neither throwing nor returning are valid here so aborting is pretty much the only solution
void boost::throw_exception(std::exception const& /*e*/, boost::source_location const& /*loc*/) {
    std::abort();
}

// Erigon treats Terminal Total Difficulty (TTD) as a JSON number. In order to guarantee at least read-only
// binary compatibility from Erigon database, we need Boost.Multiprecision because:
// - nlohmann::json treats JSON numbers that overflow 64-bit unsigned integer as floating-point numbers
// - intx::uint256 cannot currently be constructed from a floating-point number
using mp_float = boost::multiprecision::cpp_dec_float_100;
using mp_int = boost::multiprecision::cpp_int;

namespace silkworm {

static const std::vector<std::pair<std::string, const ChainConfig*>> kKnownChainConfigs{
    {"mainnet", &kMainnetConfig},
    {"ropsten", &kRopstenConfig},
    {"rinkeby", &kRinkebyConfig},
    {"goerli", &kGoerliConfig},
    {"sepolia", &kSepoliaConfig},
};

constexpr const char* kTerminalTotalDifficulty{"terminalTotalDifficulty"};
constexpr const char* kTerminalBlockNumber{"terminalBlockNumber"};
constexpr const char* kTerminalBlockHash{"terminalBlockHash"};
constexpr const char* kGenesisHash{"genesisBlockHash"};

static inline void member_to_json(nlohmann::json& json, const std::string& key, const std::optional<uint64_t>& source) {
    if (source.has_value()) {
        json[key] = source.value();
    }
}

static inline void read_json_config_member(const nlohmann::json& json, const std::string& key,
                                           std::optional<uint64_t>& target) {
    if (json.contains(key)) {
        target = json[key].get<uint64_t>();
    }
}

nlohmann::json ChainConfig::to_json() const noexcept {
    nlohmann::json ret;

    ret["chainId"] = chain_id;

    nlohmann::json empty_object(nlohmann::json::value_t::object);
    switch (seal_engine) {
        case silkworm::SealEngineType::kEthash:
            ret.emplace("ethash", empty_object);
            break;
        case silkworm::SealEngineType::kClique:
            ret.emplace("clique", empty_object);
            break;
        case silkworm::SealEngineType::kAuRA:
            ret.emplace("aura", empty_object);
            break;
        default:
            break;
    }

    for (size_t i{0}; i < EVMC_MAX_REVISION; ++i) {
        member_to_json(ret, kJsonForkNames[i], evmc_fork_blocks[i]);
    }

    member_to_json(ret, "daoForkBlock", dao_block);
    member_to_json(ret, "muirGlacierBlock", muir_glacier_block);
    member_to_json(ret, "arrowGlacierBlock", arrow_glacier_block);
    member_to_json(ret, "grayGlacierBlock", gray_glacier_block);
    member_to_json(ret, kTerminalBlockNumber, terminal_block_number);

    if (terminal_total_difficulty.has_value()) {
        // TODO (Andrew) geth probably treats terminalTotalDifficulty as a JSON number
        ret[kTerminalTotalDifficulty] = to_string(*terminal_total_difficulty);
    }

    if (terminal_block_hash.has_value()) {
        ret[kTerminalBlockHash] = to_hex(*terminal_block_hash, /*with_prefix=*/true);
    }

    if (genesis_hash.has_value()) {
        ret[kGenesisHash] = to_hex(*genesis_hash, /*with_prefix=*/true);
    }

    return ret;
}

std::optional<ChainConfig> ChainConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.contains("chainId") || !json["chainId"].is_number()) {
        return std::nullopt;
    }

    ChainConfig config{};
    config.chain_id = json["chainId"].get<uint64_t>();

    if (json.contains("ethash")) {
        config.seal_engine = SealEngineType::kEthash;
    } else if (json.contains("clique")) {
        config.seal_engine = SealEngineType::kClique;
    } else if (json.contains("aura")) {
        config.seal_engine = SealEngineType::kAuRA;
    } else {
        config.seal_engine = SealEngineType::kNoProof;
    }

    for (size_t i{0}; i < EVMC_MAX_REVISION; ++i) {
        read_json_config_member(json, kJsonForkNames[i], config.evmc_fork_blocks[i]);
    }

    read_json_config_member(json, "daoForkBlock", config.dao_block);
    read_json_config_member(json, "muirGlacierBlock", config.muir_glacier_block);
    read_json_config_member(json, "arrowGlacierBlock", config.arrow_glacier_block);
    read_json_config_member(json, "grayGlacierBlock", config.gray_glacier_block);
    read_json_config_member(json, kTerminalBlockNumber, config.terminal_block_number);

    if (json.contains(kTerminalTotalDifficulty)) {
        // We handle TTD serialized both as JSON string *and* as JSON number
        if (json[kTerminalTotalDifficulty].is_string()) {
            /* This is still present to maintain compatibility with previous Silkworm format */
            config.terminal_total_difficulty =
                intx::from_string<intx::uint256>(json[kTerminalTotalDifficulty].get<std::string>());
        } else if (json[kTerminalTotalDifficulty].is_number()) {
            /* This is for compatibility with Erigon and probably Geth which treat TTD as a JSON number */
            const auto& ttd_json_value = json[kTerminalTotalDifficulty];
            const auto ttd_as_mp_int =
                ttd_json_value.is_number_float() ? mp_int{mp_float{ttd_json_value.dump()}}
                                                 : mp_int{ttd_json_value.dump()};
            config.terminal_total_difficulty = intx::from_string<intx::uint256>(ttd_as_mp_int.str());
        }
    }

    if (json.contains(kTerminalBlockHash)) {
        auto terminal_block_hash_bytes{from_hex(json[kTerminalBlockHash].get<std::string>())};
        if (terminal_block_hash_bytes.has_value()) {
            config.terminal_block_hash = to_bytes32(*terminal_block_hash_bytes);
        }
    }

    /* Note ! genesis_hash is purposely omitted. It must be loaded from db after the
     * effective genesis block has been persisted */

    return config;
}

std::optional<uint64_t> ChainConfig::revision_block(evmc_revision rev) const noexcept {
    if (rev == EVMC_FRONTIER) {
        return 0;
    }
    size_t i{static_cast<size_t>(rev) - 1};
    return evmc_fork_blocks.at(i);
}

void ChainConfig::set_revision_block(evmc_revision rev, std::optional<uint64_t> block) {
    if (rev > 0) {  // Frontier block is always 0
        evmc_fork_blocks[static_cast<size_t>(rev) - 1] = block;
    }
}
std::vector<BlockNum> ChainConfig::distinct_fork_numbers() const {
    std::set<BlockNum> ret;

    for (const auto& block_number : evmc_fork_blocks) {
        (void)ret.insert(block_number.value_or(0));
    }

    (void)ret.insert(dao_block.value_or(0));
    (void)ret.insert(muir_glacier_block.value_or(0));
    (void)ret.insert(arrow_glacier_block.value_or(0));
    (void)ret.insert(gray_glacier_block.value_or(0));

    ret.erase(0);  // Block 0 is not a fork number
    return {ret.cbegin(), ret.cend()};
}

std::ostream& operator<<(std::ostream& out, const ChainConfig& obj) { return out << obj.to_json(); }

std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(const uint64_t chain_id) noexcept {
    auto it{
        as_range::find_if(kKnownChainConfigs, [&chain_id](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return x.second->chain_id == chain_id;
        })};

    if (it == kKnownChainConfigs.end()) {
        return std::nullopt;
    }
    return std::make_pair(it->first, it->second);
}

std::optional<std::pair<const std::string, const ChainConfig*>> lookup_known_chain(const std::string_view identifier) noexcept {
    auto it{
        as_range::find_if(kKnownChainConfigs, [&identifier](const std::pair<std::string, const ChainConfig*>& x) -> bool {
            return iequals(x.first, identifier);
        })};

    if (it == kKnownChainConfigs.end()) {
        return std::nullopt;
    }
    return std::make_pair(it->first, it->second);
}

std::map<std::string, uint64_t> get_known_chains_map() noexcept {
    std::map<std::string, uint64_t> ret;
    as_range::for_each(kKnownChainConfigs, [&ret](const std::pair<std::string, const ChainConfig*>& x) -> void {
        ret[x.first] = x.second->chain_id;
    });
    return ret;
}

}  // namespace silkworm
