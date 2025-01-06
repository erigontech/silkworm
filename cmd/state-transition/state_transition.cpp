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

#include <bit>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>

#include <nlohmann/json.hpp>

#include <silkworm/core/chain/genesis.hpp>
#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/core/protocol/param.hpp>
#include <silkworm/core/protocol/rule_set.hpp>
#include <silkworm/core/rlp/encode_vector.hpp>
#include <silkworm/core/state/in_memory_state.hpp>
#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>

#include "expected_state.hpp"

namespace silkworm::cmd::state_transition {

StateTransition::StateTransition(const std::string& file_path) noexcept {
    std::ifstream input_file(file_path);
    nlohmann::json base_json;
    input_file >> base_json;
    auto test_object = base_json.begin();
    test_name_ = test_object.key();
    test_data_ = test_object.value();
}

StateTransition::StateTransition(const nlohmann::json& json, const bool terminate_on_error, const bool show_diagnostics) noexcept
    : terminate_on_error_{terminate_on_error},
      show_diagnostics_{show_diagnostics} {
    auto test_object = json.begin();
    test_name_ = test_object.key();
    std::cout << test_name_ << ":" << std::endl;
    test_data_ = test_object.value();
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

std::vector<ExpectedState> StateTransition::get_expected_states() {
    std::vector<ExpectedState> expected_states;

    for (const auto& post_state : test_data_.at("post").items()) {
        nlohmann::json data = post_state.value();
        const std::string& key = post_state.key();
        expected_states.emplace_back(data, key);
    }

    return expected_states;
}

evmc::address StateTransition::to_evmc_address(const std::string& address) {
    evmc::address out;
    if (!address.empty()) {
        out = hex_to_address(address);
    }

    return out;
}

Block StateTransition::get_block(InMemoryState& state, ChainConfig& chain_config) {
    auto block = Block();

    block.header.beneficiary = to_evmc_address(get_env("currentCoinbase"));

    block.header.gas_limit = std::stoull(get_env("currentGasLimit"), nullptr, /*base=*/16);
    block.header.number = std::stoull(get_env("currentNumber"), nullptr, /*base=*/16);
    block.header.timestamp = std::stoull(get_env("currentTimestamp"), nullptr, /*base=*/16);
    block.header.parent_hash = to_bytes32(from_hex(get_env("previousHash")).value_or(Bytes{}));

    if (contains_env("currentRandom")) {
        block.header.prev_randao = to_bytes32(from_hex(get_env("currentRandom")).value_or(Bytes{}));
    }

    const evmc_revision rev{chain_config.revision(block.header.number, block.header.timestamp)};

    // set difficulty only for revisions before The Merge
    // current block difficulty cannot fall below minimum: https://eips.ethereum.org/EIPS/eip-2
    static constexpr uint64_t kMinDifficulty{0x20000};
    if (!chain_config.terminal_total_difficulty.has_value()) {
        block.header.difficulty = intx::from_string<intx::uint256>(get_env("currentDifficulty"));
        if (block.header.difficulty < kMinDifficulty && rev <= EVMC_LONDON) {
            block.header.difficulty = kMinDifficulty;
        }
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

    auto parent_block = Block();
    parent_block.header.gas_limit = block.header.gas_limit;
    parent_block.header.gas_used = parent_block.header.gas_limit / protocol::kElasticityMultiplier;
    parent_block.header.number = block.header.number - 1;
    parent_block.header.base_fee_per_gas = block.header.base_fee_per_gas;
    parent_block.header.ommers_hash = kEmptyListHash;
    parent_block.header.difficulty = intx::from_string<intx::uint256>(get_env("currentDifficulty"));
    state.insert_block(parent_block, block.header.parent_hash);

    return block;
}

std::unique_ptr<evmc::address> StateTransition::private_key_to_address(const std::string& private_key) {
    /// Example
    // private key: 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8
    // public key : 043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3
    // address    : 0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B

    auto private_key_bytes = from_hex(private_key).value();

    auto pair = sentry::EccKeyPair(private_key_bytes);

    uint8_t out[kAddressLength];
    auto public_key_hash = keccak256(pair.public_key().serialized());
    std::memcpy(out, public_key_hash.bytes + 12, sizeof(out));

    return std::make_unique<evmc::address>(bytes_to_address(out));
}

Transaction StateTransition::get_transaction(const ExpectedSubState& expected_sub_state) {
    Transaction txn;
    auto j_transaction = test_data_["transaction"];

    txn.nonce = std::stoull(j_transaction.at("nonce").get<std::string>(), nullptr, 16);
    txn.set_sender(*private_key_to_address(j_transaction["secretKey"]));

    const auto to_address = j_transaction.at("to").get<std::string>();
    if (!to_address.empty()) {
        txn.to = to_evmc_address(to_address);
    }
    //        std::cout << "from address: " << to_hex(txn.from.value()) << std::endl;

    if (j_transaction.contains("gasPrice")) {
        txn.type = TransactionType::kLegacy;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("gasPrice").get<std::string>());
    } else {
        txn.type = TransactionType::kDynamicFee;
        txn.max_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxFeePerGas").get<std::string>());
        txn.max_priority_fee_per_gas = intx::from_string<intx::uint256>(j_transaction.at("maxPriorityFeePerGas").get<std::string>());
    }

    if (expected_sub_state.dataIndex >= j_transaction.at("data").size()) {
        throw std::runtime_error("data index out of range");
    }
    txn.data = from_hex(j_transaction.at("data").at(expected_sub_state.dataIndex).get<std::string>()).value();

    if (expected_sub_state.gasIndex >= j_transaction.at("gasLimit").size()) {
        throw std::runtime_error("gas limit index out of range");
    }
    txn.gas_limit = std::stoull(j_transaction.at("gasLimit").at(expected_sub_state.gasIndex).get<std::string>(), nullptr, 16);

    if (expected_sub_state.valueIndex >= j_transaction.at("value").size()) {
        throw std::runtime_error("value index out of range");
    }
    auto value_str = j_transaction.at("value").at(expected_sub_state.valueIndex).get<std::string>();
    // in case of bigint, set max value; compatible with all test cases so far
    txn.value = (value_str.starts_with("0x:bigint ")) ? std::numeric_limits<intx::uint256>::max() : intx::from_string<intx::uint256>(value_str);

    if (j_transaction.contains("accessLists")) {
        auto j_access_list = j_transaction.at("accessLists").at(expected_sub_state.dataIndex);

        for (const auto& j_access_entry : j_access_list.items()) {
            AccessListEntry entry;
            entry.account = to_evmc_address(j_access_entry.value().at("address"));

            for (const auto& j_storage_key : j_access_entry.value().at("storageKeys").items()) {
                if (j_storage_key.value().is_string()) {
                    auto hex_storage = from_hex(j_storage_key.value().get<std::string>());
                    entry.storage_keys.emplace_back(to_bytes32(hex_storage.value()));
                }
            }

            txn.access_list.emplace_back(entry);
        }

        if (txn.type == TransactionType::kLegacy) {
            txn.type = TransactionType::kAccessList;
        }
    }

    return txn;
}

void StateTransition::validate_transition(const Receipt& receipt, const ExpectedState& expected_state, const ExpectedSubState& expected_sub_state, const InMemoryState& state) {
    if (expected_sub_state.exceptionExpected) {
        if (receipt.success) {
            print_error_message(expected_state, expected_sub_state, "Failed: Exception expected");
            ++failed_count_;
        }
    }

    if (state.state_root_hash() != expected_sub_state.stateHash) {
        print_error_message(expected_state, expected_sub_state, "Failed: State root hash does not match");
        ++failed_count_;
    } else {
        Bytes encoded;
        rlp::encode(encoded, receipt.logs);
        if (std::bit_cast<evmc_bytes32>(keccak256(encoded)) != expected_sub_state.logsHash) {
            print_error_message(expected_state, expected_sub_state, "Failed: Logs hash does not match");
            ++failed_count_;
        } else {
            print_diagnostic_message(expected_state, expected_sub_state, "OK");
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

/*
 * This function is used to clean up the state after a failed block execution.
 * Certain post-processing would be a part of the execute_transaction() function,
 * but since the validation failed, we need to do it manually.
 */
void cleanup_error_block(Block& block, ExecutionProcessor& processor, const evmc_revision rev) {
    if (rev >= EVMC_SHANGHAI) {
        processor.evm().state().access_account(block.header.beneficiary);
    }
    processor.evm().state().add_to_balance(block.header.beneficiary, 0);
    processor.evm().state().finalize_transaction(rev);
    processor.evm().state().write_to_db(block.header.number);
}

void StateTransition::run() {
    failed_count_ = 0;
    total_count_ = 0;

    for (auto& expected_state : get_expected_states()) {
        for (const auto& expected_sub_state : expected_state.get_sub_states()) {
            ++total_count_;
            auto config = expected_state.get_config();
            auto rule_set = protocol::rule_set_factory(config);
            auto state = read_genesis_allocation(test_data_["pre"]);
            auto block = get_block(state, config);
            auto txn = get_transaction(expected_sub_state);

            ExecutionProcessor processor{block, *rule_set, state, config, true};
            Receipt receipt;

            const evmc_revision rev{config.revision(block.header.number, block.header.timestamp)};

            auto pre_block_validation = rule_set->pre_validate_block_body(block, state);
            auto block_validation = rule_set->validate_block_header(block.header, state, true);
            auto pre_txn_validation = protocol::pre_validate_transaction(txn, rev, config.chain_id, block.header.base_fee_per_gas, block.header.blob_gas_price());
            auto txn_validation = protocol::validate_transaction(txn, processor.evm().state(), processor.available_gas());

            // std::cout << "pre: " << std::endl;
            // state->print_state_root_hash();

            if (pre_block_validation == ValidationResult::kOk &&
                block_validation == ValidationResult::kOk &&
                pre_txn_validation == ValidationResult::kOk &&
                txn_validation == ValidationResult::kOk) {
                processor.execute_transaction(txn, receipt);
                processor.evm().state().write_to_db(block.header.number);
            } else {
                cleanup_error_block(block, processor, rev);
                receipt.success = false;
            }

            // std::cout << "post: " << std::endl;
            // state->print_state_root_hash();

            validate_transition(receipt, expected_state, expected_sub_state, state);
        }
    }

    if (show_diagnostics_) {
        std::cout << "[" << test_name_ << "] "
                  << "Finished total " << total_count_ << ", failed " << failed_count_ << std::endl
                  << std::endl;
    }
}
}  // namespace silkworm::cmd::state_transition
