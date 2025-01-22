/*
   Copyright 2023 The Silkworm Authors

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

#include <set>
#include <string>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/types/address.hpp>

namespace silkworm::protocol::bor {

uint64_t Config::sprint_size(BlockNum block_num) const noexcept {
    const uint64_t* size = config_value_lookup(sprint, block_num);
    SILKWORM_ASSERT(size);
    return *size;
}

nlohmann::json Config::to_json() const noexcept {
    nlohmann::json ret;
    for (const auto& [from, val] : period) {
        ret["period"][std::to_string(from)] = val;
    }
    for (const auto& [from, val] : sprint) {
        ret["sprint"][std::to_string(from)] = val;
    }
    ret["validatorContract"] = to_hex(validator_contract.bytes, /*with_prefix=*/true);
    for (const auto& [block, rewrites] : rewrite_code) {
        const std::string block_str{std::to_string(block)};
        for (const auto& [address, code] : rewrites) {
            const std::string code_hex{to_hex(string_view_to_byte_view(code), /*with_prefix=*/true)};
            ret["blockAlloc"][block_str][to_hex(address.bytes, true)]["code"] = code_hex;
        }
    }
    ret["jaipurBlock"] = jaipur_block;
    ret["agraBlock"] = agra_block;
    return ret;
}

std::optional<Config> Config::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.is_object()) {
        return std::nullopt;
    }

    Config config;

    std::vector<std::pair<BlockNum, uint64_t>> period;
    for (const auto& item : json["period"].items()) {
        const BlockNum from{std::stoull(item.key(), nullptr, 0)};
        period.emplace_back(from, item.value().get<uint64_t>());
    }
    if (period.size() > SmallMap<BlockNum, uint64_t>::max_size()) {
        return std::nullopt;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Warray-bounds"
    // silence misdiagnostics in gcc 14
    config.period = {period.begin(), period.end()};
#pragma GCC diagnostic pop

    std::vector<std::pair<BlockNum, uint64_t>> sprint;
    for (const auto& item : json["sprint"].items()) {
        const BlockNum from{std::stoull(item.key(), nullptr, 0)};
        sprint.emplace_back(from, item.value().get<uint64_t>());
    }
    if (sprint.size() > SmallMap<BlockNum, uint64_t>::max_size()) {
        return std::nullopt;
    }
    config.sprint = {sprint.begin(), sprint.end()};

    config.validator_contract = hex_to_address(json["validatorContract"].get<std::string>(), /*return_zero_on_err=*/true);
    if (is_zero(config.validator_contract)) {
        return std::nullopt;
    }

    SILKWORM_THREAD_LOCAL std::set<Bytes> codes;
    if (json.contains("blockAlloc")) {
        std::vector<std::pair<BlockNum, SmallMap<evmc::address, std::string_view>>> out_vec;
        for (const auto& outer : json["blockAlloc"].items()) {
            const BlockNum block_num = std::stoull(outer.key(), nullptr, 0);
            std::vector<std::pair<evmc::address, std::string_view>> inner_vec;
            for (const auto& inner : outer.value().items()) {
                const evmc::address contract{hex_to_address(inner.key(), /*return_zero_on_err=*/true)};
                if (is_zero(contract)) {
                    return std::nullopt;
                }
                const std::optional<Bytes> code{from_hex(inner.value()["code"].get<std::string>())};
                if (!code) {
                    return std::nullopt;
                }
                auto code_it{codes.find(*code)};
                if (code_it == codes.end()) {
                    code_it = codes.insert(*code).first;
                }
                inner_vec.emplace_back(contract, byte_view_to_string_view(*code_it));
            }
            out_vec.emplace_back(block_num, SmallMap<evmc::address, std::string_view>{inner_vec.begin(), inner_vec.end()});
        }
        config.rewrite_code = {out_vec.begin(), out_vec.end()};
    }

    config.jaipur_block = json["jaipurBlock"].get<BlockNum>();
    config.agra_block = json["agraBlock"].get<BlockNum>();
    return config;
}

}  // namespace silkworm::protocol::bor
