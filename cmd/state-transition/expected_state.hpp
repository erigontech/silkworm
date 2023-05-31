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

#pragma once

#include <utility>

#include <nlohmann/json.hpp>

#include "silkworm/core/common/test_util.hpp"

namespace silkworm::cmd::state_transition {

class ExpectedSubState {
  public:
    unsigned index{};
    evmc::bytes32 stateHash;
    evmc::bytes32 logsHash;
    unsigned long dataIndex{};
    unsigned long gasIndex{};
    unsigned long valueIndex{};
    bool exceptionExpected{false};
    std::string exceptionMessage;
};

class ExpectedState {
    nlohmann::json state_data_;
    std::string fork_name_;

  public:
    explicit ExpectedState(const nlohmann::json& data, const std::string& name) noexcept {
        state_data_ = data;
        fork_name_ = name;
    }

    [[nodiscard]] ChainConfig get_config() const;

    std::vector<ExpectedSubState> get_sub_states();

    [[nodiscard]] std::string fork_name() const { return fork_name_; };
};
};  // namespace silkworm::cmd::state_transition
