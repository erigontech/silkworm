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

#include <iostream>
#include <memory>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "cmd/state-transition/expected_state.hpp"
#include "silkworm/core/common/cast.hpp"
#include "silkworm/core/execution/execution.hpp"
#include "silkworm/core/protocol/rule_set.hpp"
#include "silkworm/core/rlp/encode_vector.hpp"
#include "silkworm/core/state/in_memory_state.hpp"
#include "silkworm/sentry/common/ecc_key_pair.hpp"
#include "third_party/ethash/include/ethash/keccak.hpp"

namespace silkworm::cmd::state_transition {
class StateTransition {
  private:
    nlohmann::json test_data_;
    std::string test_name_;
    unsigned total_count_{};
    unsigned failed_count_{};
    bool terminate_on_error_;

  public:
    explicit StateTransition(const std::string& fileName, bool terminate_on_error) noexcept;

    std::string name();
    std::string get_env(const std::string& key);
    bool contains_env(const std::string& key);
    std::vector<ExpectedState> get_expected_states();
    static evmc::address to_evmc_address(const std::string& address);
    silkworm::Block get_block();
    std::unique_ptr<silkworm::InMemoryState> get_state();
    static std::unique_ptr<evmc::address> private_key_to_address(const std::string& privateKey);
    silkworm::Transaction get_transaction(ExpectedSubState expectedStateTransaction);
    void validate_transition(const silkworm::Receipt& receipt, const ExpectedState& expectedState, const ExpectedSubState& expectedSubState, const InMemoryState& state);
    static void print_validation_results(const ExpectedState& expectedState, const ExpectedSubState& expectedSubState, const std::string& result);
    void run();
};
}  // namespace silkworm::cmd::state_transition
