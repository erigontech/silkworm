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

#include "transition_configuration.hpp"

#include <silkworm/core/common/util.hpp>

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
