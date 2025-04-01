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

#include "chain_config.hpp"

#include <sstream>

#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::string chain_config_to_string(const ChainConfig& chain_config) {
    std::stringstream out;
    out << "genesis: " << to_hex(chain_config.genesis_hash.value_or(evmc::bytes32{})) << " "
        << "config: " << chain_config.to_json().dump();
    return out.str();
}

std::ostream& operator<<(std::ostream& out, const ChainConfig& chain_config) {
    out << chain_config_to_string(chain_config);
    return out;
}

}  // namespace silkworm::rpc
