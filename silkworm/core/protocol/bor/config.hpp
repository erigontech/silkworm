// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <string_view>

#include <evmc/evmc.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/small_map.hpp>

namespace silkworm::protocol::bor {

struct Config {
    SmallMap<BlockNum, uint64_t> period;
    SmallMap<BlockNum, uint64_t> sprint;  // from block -> sprint size

    evmc::address validator_contract;

    SmallMap<BlockNum, SmallMap<evmc::address, std::string_view>> rewrite_code;

    BlockNum jaipur_block{0};

    // https://forum.polygon.technology/t/pip-28-agra-hardfork
    BlockNum agra_block{0};

    uint64_t sprint_size(BlockNum block_num) const noexcept;

    nlohmann::json to_json() const noexcept;

    static std::optional<Config> from_json(const nlohmann::json& json) noexcept;

    bool operator==(const Config&) const = default;
};

// Looks up a config value as of a given block number.
// The assumption here is that config is a càdlàg map of starting_from_block -> value.
// For example, config of {{0, "a"}, {10, "b"}, {20, "c"}}
// means that the config value is "a" for blocks 0–9,
// "b" for blocks 10–19, and "c" for block 20 and above.
//
// N.B. Similar to borKeyValueConfigHelper in Erigon.
template <typename T>
constexpr const T* config_value_lookup(const SmallMap<BlockNum, T>& config, BlockNum block_num) noexcept {
    auto it{config.begin()};
    if (config.empty() || it->first > block_num) {
        return nullptr;
    }
    for (; (it + 1) != config.end(); ++it) {
        if (it->first <= block_num && block_num < (it + 1)->first) {
            return &(it->second);
        }
    }
    return &(it->second);
}

}  // namespace silkworm::protocol::bor
