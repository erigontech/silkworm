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

#include "bor_config.hpp"

#include <set>
#include <string>

#include <silkworm/core/common/assert.hpp>
#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/address.hpp>

namespace silkworm::protocol {

uint64_t BorConfig::sprint_size(BlockNum number) const noexcept {
    const uint64_t* size{bor_config_value_lookup(sprint, number)};
    SILKWORM_ASSERT(size);
    return *size;
}

nlohmann::json BorConfig::to_json() const noexcept {
    nlohmann::json ret;
    for (const auto& [from, val] : period) {
        ret["period"][std::to_string(from)] = val;
    }
    for (const auto& [from, val] : sprint) {
        ret["sprint"][std::to_string(from)] = val;
    }
    for (const auto& [block, rewrites] : rewrite_code) {
        const std::string block_str{std::to_string(block)};
        for (const auto& [address, code] : rewrites) {
            const std::string code_hex{to_hex(string_view_to_byte_view(code), true)};
            ret["blockAlloc"][block_str][to_hex(address.bytes, true)]["code"] = code_hex;
        }
    }
    ret["jaipurBlock"] = jaipur_block;
    if (agra_block) {
        ret["agraBlock"] = *agra_block;
    }
    return ret;
}

std::optional<BorConfig> BorConfig::from_json(const nlohmann::json& json) noexcept {
    if (json.is_discarded() || !json.is_object()) {
        return std::nullopt;
    }

    BorConfig config;

    std::vector<std::pair<BlockNum, uint64_t>> period;
    for (const auto& item : json["period"].items()) {
        const BlockNum from{std::stoull(item.key(), nullptr, 0)};
        period.emplace_back(from, item.value().get<uint64_t>());
    }
    config.period = {period.begin(), period.end()};

    std::vector<std::pair<BlockNum, uint64_t>> sprint;
    for (const auto& item : json["sprint"].items()) {
        const BlockNum from{std::stoull(item.key(), nullptr, 0)};
        sprint.emplace_back(from, item.value().get<uint64_t>());
    }
    config.sprint = {sprint.begin(), sprint.end()};

    SILKWORM_THREAD_LOCAL std::set<Bytes> codes;
    if (json.contains("blockAlloc")) {
        std::vector<std::pair<BlockNum, SmallMap<evmc::address, std::string_view>>> out_vec;
        for (const auto& outer : json["blockAlloc"].items()) {
            const BlockNum num{std::stoull(outer.key(), nullptr, 0)};
            std::vector<std::pair<evmc::address, std::string_view>> inner_vec;
            for (const auto& inner : outer.value().items()) {
                const evmc::address contract{hex_to_address(inner.key())};
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
            out_vec.emplace_back(num, SmallMap<evmc::address, std::string_view>{inner_vec.begin(), inner_vec.end()});
        }
        config.rewrite_code = {out_vec.begin(), out_vec.end()};
    }

    config.jaipur_block = json["jaipurBlock"].get<BlockNum>();
    if (json.contains("agraBlock")) {
        config.agra_block = json["agraBlock"].get<BlockNum>();
    }
    return config;
}

}  // namespace silkworm::protocol
