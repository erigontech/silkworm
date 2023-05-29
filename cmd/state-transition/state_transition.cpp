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

#include "state_transition.hpp"

#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include "cmd/state-transition/expected_state.hpp"
#include "silkworm/core/common/cast.hpp"
#include "silkworm/core/execution/execution.hpp"
#include "silkworm/core/protocol/param.hpp"
#include "silkworm/core/protocol/rule_set.hpp"
#include "silkworm/core/rlp/encode_vector.hpp"
#include "silkworm/core/state/in_memory_state.hpp"
#include "silkworm/sentry/common/ecc_key_pair.hpp"
#include "third_party/ethash/include/ethash/keccak.hpp"

namespace silkworm::cmd::state_transition {

StateTransition::StateTransition(const std::string& file_path) noexcept {
    std::ifstream input_file(file_path);
    nlohmann::json baseJson;
    input_file >> baseJson;
    auto testObject = baseJson.begin();
    test_name_ = testObject.key();
    test_data_ = testObject.value();

    terminate_on_error_ = false;
    show_diagnostics_ = false;
}

StateTransition::StateTransition(const nlohmann::json& json, const bool terminate_on_error, const bool show_diagnostics) noexcept {
    auto testObject = json.begin();
    test_name_ = testObject.key();
    std::cout << test_name_ << ":" << std::endl;

    test_data_ = testObject.value();

    terminate_on_error_ = terminate_on_error;
    show_diagnostics_ = show_diagnostics;
}

std::string StateTransition::name() {
    return test_name_;
}

std::string StateTransition::get_env(const std::string& key) {
    return test_data_.at("env").at(key);
}
bool StateTransition::contains_env(const std::string& key) {
    return test_data_.at("env").contains(key);
}

// get transaction
std::vector<ExpectedState> StateTransition::get_expected_states() {
    std::vector<ExpectedState> expectedStates;

    auto post = test_data_.at("post");

    for (const auto& postState : post.items()) {
        nlohmann::json data = postState.value();
        const std::string& key = postState.key();
        expectedStates.emplace_back(data, key);
    }

    return expectedStates;
}

evmc::address StateTransition::to_evmc_address(const std::string& address) {
    evmc::address out;
    if (!address.empty()) {
        auto bytes = silkworm::from_hex(address);
        out = silkworm::to_evmc_address(bytes.value_or(Bytes{}));
    }

    return out;
}

// get block
silkworm::Block StateTransition::get_block(protocol::IRuleSet& /*rule_set*/, InMemoryState& state, ChainConfig& chain_config) {
    auto block = silkworm::Block();

    block.header.beneficiary = to_evmc_address(get_env("currentCoinbase"));

    block.header.gas_limit = std::stoull(get_env("currentGasLimit"), nullptr, /*base=*/16);
    block.header.number = std::stoull(get_env("currentNumber"), nullptr, /*base=*/16);
    block.header.timestamp = std::stoull(get_env("currentTimestamp"), nullptr, /*base=*/16);
    block.header.parent_hash = to_bytes32(silkworm::from_hex(get_env("previousHash")).value_or(silkworm::Bytes{}));

    if (contains_env("currentRandom")) {
        block.header.prev_randao = to_bytes32(silkworm::from_hex(get_env("currentRandom")).value_or(silkworm::Bytes{}));
    }

    const evmc_revision rev{chain_config.revision(block.header.number, block.header.timestamp)};

//    if (rev <= EVMC_LONDON) {
    if (!chain_config.terminal_total_difficulty.has_value()) {
        block.header.difficulty = intx::from_string<intx::uint256>(get_env("currentDifficulty"));
    }

    if (contains_env("currentBaseFee") && rev >= EVMC_LONDON) {
        block.header.base_fee_per_gas = intx::from_string<intx::uint256>(get_env("currentBaseFee"));
    }

    if (rev >= EVMC_SHANGHAI) {
        block.withdrawals = std::vector<Withdrawal>{};
        block.header.withdrawals_root = kEmptyRoot;
    }

    block.header.transactions_root = protocol::compute_transaction_root(block);
    block.header.ommers_hash = kEmptyListHash;

    auto parent_block = silkworm::Block();
    parent_block.header.gas_limit = block.header.gas_limit;
    parent_block.header.gas_used = parent_block.header.gas_limit / protocol::kElasticityMultiplier;
    parent_block.header.number = block.header.number - 1;
    parent_block.header.base_fee_per_gas = block.header.base_fee_per_gas;
    state.insert_block(parent_block, block.header.parent_hash);

    return block;
}

std::unique_ptr<silkworm::InMemoryState> StateTransition::get_state() {
    auto state = std::make_unique<silkworm::InMemoryState>();

    auto pre = test_data_["pre"];

    for (const auto& preState : pre.items()) {
        const auto address = to_evmc_address(preState.key());
        const nlohmann::json preStateValue = preState.value();

        auto account = silkworm::Account();
        account.balance = intx::from_string<intx::uint256>(preStateValue.at("balance"));
        account.nonce = std::stoull(std::string(preStateValue.at("nonce")), nullptr, 16);

        const Bytes code{from_hex(std::string(preStateValue.at("code"))).value()};
        account.code_hash = silkworm::bit_cast<evmc_bytes32>(keccak256(code));
        account.incarnation = kDefaultIncarnation;

        state->update_account(address, /*initial=*/std::nullopt, account);
        state->update_account_code(address, account.incarnation, account.code_hash, code);

        for (const auto& storage : preStateValue.at("storage").items()) {
            Bytes key{from_hex(storage.key()).value()};
            Bytes value{from_hex(storage.value().get<std::string>()).value()};
            state->update_storage(address, account.incarnation, to_bytes32(key), /*initial=*/{}, to_bytes32(value));
        }
    }

    return state;
}

std::unique_ptr<evmc::address> StateTransition::private_key_to_address(const std::string& private_key) {
    /// Example
    // private key: 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8
    // public key : 043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3
    // address    : 0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B

    auto private_key_bytes = from_hex(private_key).value();

    silkworm::sentry::common::EccKeyPair pair = silkworm::sentry::common::EccKeyPair(private_key_bytes);

    uint8_t out[20];
    auto public_key_hash = keccak256(pair.public_key().serialized());
    std::memcpy(out, public_key_hash.bytes + 12, sizeof(out));

    return std::make_unique<evmc::address>(silkworm::to_evmc_address(out));
}

silkworm::Transaction StateTransition::get_transaction(ExpectedSubState expected_sub_state) {
    silkworm::Transaction txn;
    auto jTransaction = test_data_["transaction"];

    txn.nonce = std::stoull(jTransaction.at("nonce").get<std::string>(), nullptr, 16);
    txn.from = *private_key_to_address(jTransaction["secretKey"]);

    const auto to_address = jTransaction.at("to").get<std::string>();
    if (!to_address.empty()) {
        txn.to = to_evmc_address(to_address);
    }
    //        std::cout << "from address: " << to_hex(txn.from.value()) << std::endl;

    if (jTransaction.contains("gasPrice")) {
        txn.type = silkworm::TransactionType::kLegacy;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("gasPrice").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("gasPrice").get<std::string>());
    } else {
        txn.type = silkworm::TransactionType::kEip1559;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("maxFeePerGas").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("maxPriorityFeePerGas").get<std::string>());
    }

    if (expected_sub_state.dataIndex >= jTransaction.at("data").size()) {
        throw std::runtime_error("data index out of range");
    } else {
        txn.data = from_hex(jTransaction.at("data").at(expected_sub_state.dataIndex).get<std::string>()).value();
    }

    if (expected_sub_state.gasIndex >= jTransaction.at("gasLimit").size()) {
        throw std::runtime_error("gas limit index out of range");
    } else {
        txn.gas_limit = std::stoull(jTransaction.at("gasLimit").at(expected_sub_state.gasIndex).get<std::string>(), nullptr, 16);
    }

    if (expected_sub_state.valueIndex >= jTransaction.at("value").size()) {
        throw std::runtime_error("value index out of range");
    } else {
        auto value_str = jTransaction.at("value").at(expected_sub_state.valueIndex).get<std::string>();
        // in case of bigint, set max value; compatible with all test cases so far
        txn.value = (value_str.starts_with("0x:bigint ")) ? std::numeric_limits<intx::uint256>::max() : intx::from_string<intx::uint256>(value_str);
    }

    return txn;
}

void StateTransition::validate_transition(const silkworm::Receipt& receipt, const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const InMemoryState& state) {
    if (expected_sub_state.exceptionExpected) {
        if (receipt.success) {
            print_error_message(expected_state, expected_sub_state, "Failed: Exception expected");
            ++failed_count_;
        } else {
            print_diagnostic_message(expected_state, expected_sub_state, "OK (Exception Expected)");
        }
    } else {
        if (state.state_root_hash() != expected_sub_state.stateHash) {
            print_error_message(expected_state, expected_sub_state, "Failed: State root hash does not match");
            failed_count_++;
        } else {
            Bytes encoded;
            rlp::encode(encoded, receipt.logs);
            if (silkworm::bit_cast<evmc_bytes32>(keccak256(encoded)) != expected_sub_state.logsHash) {
                print_error_message(expected_state, expected_sub_state, "Failed: Logs hash does not match");
                failed_count_++;
            } else {
                print_diagnostic_message(expected_state, expected_sub_state, "OK");
            }
        }
    }
}

void StateTransition::print_error_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
    if (terminate_on_error_) {
        throw std::runtime_error(message);
    }
    print_message(expected_state, expected_sub_state, message);
}

void StateTransition::print_diagnostic_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
    if (show_diagnostics_) {
        print_message(expected_state, expected_sub_state, message);
    }
}

void StateTransition::print_message(const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const std::string& message) {
    std::cout << "[" << test_name_ << ":" << expected_state.fork_name() << ":" << expected_sub_state.index << "] " << message << std::endl;
}

void StateTransition::run() {
    failed_count_ = 0;
    total_count_ = 0;

    for (auto& expectedState : get_expected_states()) {
        for (const auto& expectedSubState : expectedState.get_sub_states()) {
            ++total_count_;
            auto config = expectedState.get_config();
            auto ruleSet = protocol::rule_set_factory(config);
            auto state = get_state();
            auto block = get_block(*ruleSet, *state, config);
            auto txn = get_transaction(expectedSubState);

            silkworm::ExecutionProcessor processor{block, *ruleSet, *state, config};
            silkworm::Receipt receipt;

            auto pre_validation = ruleSet->pre_validate_block_body(block, *state);
            auto block_validation = ruleSet->validate_block_header(block.header, *state, true);
            auto txn_validation = processor.validate_transaction(txn);

            // std::cout << "pre: " << std::endl;
            // state->print_state_root_hash();

            if (pre_validation == ValidationResult::kOk && block_validation == ValidationResult::kOk && txn_validation == ValidationResult::kOk) {
                processor.execute_transaction(txn, receipt);
                processor.evm().state().write_to_db(block.header.number);
            } else {
                receipt.success = false;
            }

            // std::cout << "post: " << std::endl;
            // state->print_state_root_hash();

            validate_transition(receipt, expectedState, expectedSubState, *state);
        }
    }

    if (show_diagnostics_) {
        std::cout << "[" << test_name_ << "] "
                  << "Finished total " << total_count_ << ", failed " << failed_count_ << std::endl
                  << std::endl;
    }
}
};  // namespace silkworm::cmd::state_transition
