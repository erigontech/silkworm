// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <utility>

#include <nlohmann/json.hpp>

#include "silkworm/core/common/test_util.hpp"

namespace silkworm::cmd::state_transition {

class ExpectedSubState {
  public:
    unsigned index{};
    evmc::bytes32 stateHash;
    evmc::bytes32 logsHash;
    uint64_t dataIndex{};
    uint64_t gasIndex{};
    uint64_t valueIndex{};
    bool exceptionExpected{false};
    std::string exceptionMessage;
};

class ExpectedState {
    nlohmann::json state_data_;
    std::string fork_name_;

  public:
    ExpectedState(
        nlohmann::json state_data,
        std::string fork_name)
        : state_data_{std::move(state_data)},
          fork_name_{std::move(fork_name)} {}

    ChainConfig get_config() const;

    std::vector<ExpectedSubState> get_sub_states();

    std::string fork_name() const { return fork_name_; };
};
};  // namespace silkworm::cmd::state_transition
