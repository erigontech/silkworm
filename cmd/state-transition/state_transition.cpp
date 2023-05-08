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

#include "state_transition.hpp"

#include <fstream>
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
StateTransition::StateTransition(const std::string& fileName, const bool terminate_on_error) noexcept {
    std::string basePath = "/home/jacek/dev/silkworm/cmd/state-transition/";
    std::ifstream input_file(basePath + fileName);
    nlohmann::json baseJson;
    input_file >> baseJson;
    auto testObject = baseJson.begin();
    test_name_ = testObject.key();
    test_data_ = testObject.value();

    terminate_on_error_ = terminate_on_error;
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
silkworm::Block StateTransition::get_block() {
    auto block = silkworm::Block();

    block.header.beneficiary = to_evmc_address(get_env("currentCoinbase"));
    block.header.difficulty = intx::from_string<intx::uint256>(get_env("currentDifficulty"));
    block.header.gas_limit = std::stoull(get_env("currentGasLimit"), nullptr, /*base=*/16);
    block.header.number = std::stoull(get_env("currentNumber"), nullptr, /*base=*/16);
    block.header.timestamp = std::stoull(get_env("currentTimestamp"), nullptr, /*base=*/16);
    block.header.parent_hash = to_bytes32(silkworm::from_hex(get_env("previousHash")).value_or(silkworm::Bytes{}));

    if (contains_env("currentRandom")) {
        block.header.mix_hash = to_bytes32(silkworm::from_hex(get_env("currentRandom")).value_or(silkworm::Bytes{}));
    }

    if (contains_env("currentBaseFee")) {
        block.header.base_fee_per_gas = intx::from_string<intx::uint256>(get_env("currentBaseFee"));
    }

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

std::unique_ptr<evmc::address> StateTransition::private_key_to_address(const std::string& privateKey) {
    /// Example
    // private key: 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8
    // public key : 043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3
    // address    : 0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B

    auto private_key = from_hex(privateKey).value();

    silkworm::sentry::common::EccKeyPair pair = silkworm::sentry::common::EccKeyPair(private_key);

    uint8_t out[20];
    auto public_key_hash = keccak256(pair.public_key().serialized());
    std::memcpy(out, public_key_hash.bytes + 12, sizeof(out));

    return std::make_unique<evmc::address>(silkworm::to_evmc_address(out));
}

silkworm::Transaction StateTransition::get_transaction(ExpectedSubState expectedStateTransaction) {
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
        txn.type = silkworm::Transaction::Type::kLegacy;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("gasPrice").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("gasPrice").get<std::string>());
    } else {
        txn.type = silkworm::Transaction::Type::kEip1559;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("maxFeePerGas").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(jTransaction.at("maxPriorityFeePerGas").get<std::string>());
    }

    if (expectedStateTransaction.dataIndex >= jTransaction.at("data").size()) {
        throw std::runtime_error("data index out of range");
    } else {
        txn.data = from_hex(jTransaction.at("data").at(expectedStateTransaction.dataIndex).get<std::string>()).value();
    }

    if (expectedStateTransaction.gasIndex >= jTransaction.at("gasLimit").size()) {
        throw std::runtime_error("gas limit index out of range");
    } else {
        txn.gas_limit = std::stoull(jTransaction.at("gasLimit").at(expectedStateTransaction.gasIndex).get<std::string>(), nullptr, 16);
    }

    if (expectedStateTransaction.valueIndex >= jTransaction.at("value").size()) {
        throw std::runtime_error("value index out of range");
    } else {
        txn.value = intx::from_string<intx::uint256>(jTransaction.at("value").at(expectedStateTransaction.valueIndex).get<std::string>());
    }

    return txn;
}

void StateTransition::validate_transition(const silkworm::Receipt& receipt, const ExpectedState& expectedState, const ExpectedSubState& expectedSubState, const InMemoryState& state) {
    if (state.state_root_hash() != expectedSubState.stateHash) {
        failed_count_++;
        print_validation_results(expectedState, expectedSubState, "State root hash does not match");
        if (terminate_on_error_) {
            throw std::runtime_error("State root hash does not match");
        }
    } else {
        Bytes encoded;
        rlp::encode(encoded, receipt.logs);
        if (silkworm::bit_cast<evmc_bytes32>(keccak256(encoded)) != expectedSubState.logsHash) {
            failed_count_++;
            print_validation_results(expectedState, expectedSubState, "Logs hash does not match");
            if (terminate_on_error_) {
                throw std::runtime_error("Logs hash does not match");
            }
        }
    }
}

void StateTransition::print_validation_results(const ExpectedState& expectedState, const ExpectedSubState& expectedSubState, const std::string& result) {
    std::cout << "[" << expectedState.fork_name() << ":" << expectedSubState.index << "] Data: " << expectedSubState.dataIndex << ", Gas: " << expectedSubState.gasIndex << ", Value: " << expectedSubState.valueIndex << ", Result: " << result << std::endl;
}

void StateTransition::run() {
    failed_count_ = 0;
    total_count_ = 0;

    for (auto& expectedState : get_expected_states()) {
        for (const auto& expectedSubState : expectedState.get_sub_states()) {
            ++total_count_;
            auto config = expectedState.get_config();
            auto ruleSet = protocol::rule_set_factory(config);
            auto block = get_block();
            auto state = get_state();

            //                std::cout << "pre: " << std::endl;
            //                state->state_root_hash();

            silkworm::ExecutionProcessor processor{block, *ruleSet, *state, config};
            silkworm::Receipt receipt;
            auto txn = get_transaction(expectedSubState);

            //                std::cout << to_hex(txn.data) << std::endl;

            processor.execute_transaction(txn, receipt);

            processor.evm().state().write_to_db(block.header.number);

            //                std::cout << "post: " << std::endl;
            //                state->state_root_hash();

            validate_transition(receipt, expectedState, expectedSubState, *state);
        }
    }

    std::cout << "Finished, encountered " << failed_count_ << "/" << total_count_ << " errors";
}
};  // namespace silkworm::cmd::state_transition
