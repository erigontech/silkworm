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

#include "expected_state.hpp"

#include <iostream>

#include <nlohmann/json.hpp>

#include <silkworm/core/types/evmc_bytes32.hpp>

#include "silkworm/core/chain/config.hpp"
#include "silkworm/core/common/test_util.hpp"

namespace silkworm::cmd::state_transition {

ChainConfig ExpectedState::get_config() const {
    const auto config_it{test::kNetworkConfig.find(fork_name_)};
    if (config_it == test::kNetworkConfig.end()) {
        std::cout << "unknown network " << fork_name_ << std::endl;
        throw std::invalid_argument(fork_name_);
    }
    const ChainConfig& config{config_it->second};
    return config;
}

std::vector<ExpectedSubState> ExpectedState::get_sub_states() {
    std::vector<ExpectedSubState> sub_states;
    unsigned i = 0;

    for (auto& tx : state_data_) {
        ExpectedSubState subState;

        subState.stateHash = to_bytes32(from_hex(tx["hash"].get<std::string>()).value_or(Bytes{}));
        subState.logsHash = to_bytes32(from_hex(tx["logs"].get<std::string>()).value_or(Bytes{}));
        subState.dataIndex = tx["indexes"]["data"].get<uint64_t>();
        subState.gasIndex = tx["indexes"]["gas"].get<uint64_t>();
        subState.valueIndex = tx["indexes"]["value"].get<uint64_t>();
        if (tx.contains("expectException")) {
            subState.exceptionExpected = true;
            subState.exceptionMessage = tx["expectException"];
        } else {
            subState.exceptionExpected = false;
        }

        subState.index = i;
        sub_states.push_back(subState);
        ++i;
    }

    return sub_states;
}
};  // namespace silkworm::cmd::state_transition