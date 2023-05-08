//
// Created by jacek on 4/17/23.
//

#include "expected_state.hpp"

#include <iostream>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/config.hpp>

silkworm::ChainConfig ExpectedState::get_config() const {
    const auto config_it{kNetworkConfig.find(fork_name_)};
    if (config_it == kNetworkConfig.end()) {
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

        subState.stateHash = silkworm::to_bytes32(from_hex(tx["hash"].get<std::string>()).value_or(Bytes{}));
        subState.logsHash = silkworm::to_bytes32(from_hex(tx["logs"].get<std::string>()).value_or(Bytes{}));
        subState.dataIndex = tx["indexes"]["data"].get<unsigned long>();
        subState.gasIndex = tx["indexes"]["gas"].get<unsigned long>();
        subState.valueIndex = tx["indexes"]["value"].get<unsigned long>();
        subState.index = i;
        sub_states.push_back(subState);
        ++i;
    }

    return sub_states;
}
