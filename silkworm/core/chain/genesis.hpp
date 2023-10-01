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

#pragma once

#include <string_view>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/block.hpp>

// See https://arvanaghi.com/blog/explaining-the-genesis-block-in-ethereum/

namespace silkworm {

/*
 * \brief Returns genesis data given a known chain_id.
 * If id is not recognized returns an invalid json string
 */
std::string_view read_genesis_data(ChainId chain_id);

BlockHeader read_genesis_header(const nlohmann::json& genesis, const evmc::bytes32& state_root);

InMemoryState read_genesis_allocation(const nlohmann::json& alloc);

}  // namespace silkworm
