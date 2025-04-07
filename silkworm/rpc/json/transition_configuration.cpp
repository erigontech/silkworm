// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "transition_configuration.hpp"

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const TransitionConfiguration& transition_configuration) {
    json["terminalTotalDifficulty"] = to_quantity(transition_configuration.terminal_total_difficulty);
    json["terminalBlockHash"] = transition_configuration.terminal_block_hash;
    json["terminalBlockNumber"] = to_quantity(transition_configuration.terminal_block_num);
}

void from_json(const nlohmann::json& json, TransitionConfiguration& transition_configuration) {
    transition_configuration = TransitionConfiguration{
        .terminal_total_difficulty = json.at("terminalTotalDifficulty").get<intx::uint256>(),
        .terminal_block_hash = json.at("terminalBlockHash").get<evmc::bytes32>(),
        .terminal_block_num = static_cast<BlockNum>(std::stol(json.at("terminalBlockNumber").get<std::string>(), nullptr, 16))};
}

}  // namespace silkworm::rpc
