// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "expected_state.hpp"

#include <iostream>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/test_util.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>

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
        ExpectedSubState sub_state;

        sub_state.stateHash = to_bytes32(from_hex(tx["hash"].get<std::string>()).value_or(Bytes{}));
        sub_state.logsHash = to_bytes32(from_hex(tx["logs"].get<std::string>()).value_or(Bytes{}));
        sub_state.dataIndex = tx["indexes"]["data"].get<uint64_t>();
        sub_state.gasIndex = tx["indexes"]["gas"].get<uint64_t>();
        sub_state.valueIndex = tx["indexes"]["value"].get<uint64_t>();
        if (tx.contains("expectException")) {
            sub_state.exceptionExpected = true;
            sub_state.exceptionMessage = tx["expectException"];
        } else {
            sub_state.exceptionExpected = false;
        }

        sub_state.index = i;
        sub_states.push_back(sub_state);
        ++i;
    }

    return sub_states;
}
};  // namespace silkworm::cmd::state_transition