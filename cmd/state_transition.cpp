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

#include <iostream>
#include <memory>
#include <stdexcept>

#include <CLI/CLI.hpp>
#include <ethash/keccak.h>
#include <ethash/keccak.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/common/cast.hpp>
#include <silkworm/core/crypto/ecdsa.c>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/sentry/common/ecc_key_pair.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>

#include "ExpectedState.hpp"
#include "silkworm/core/state/in_memory_state.hpp"

// #include "state_transition.hpp"

namespace {
class StateTransition {
    nlohmann::json testData;
    std::string testName;

  public:
    explicit StateTransition(const std::string& fileName) noexcept {
        std::string basePath = "/home/jacek/dev/silkworm/cmd/";
        std::ifstream input_file(basePath + fileName);
        nlohmann::json baseJson;
        input_file >> baseJson;
        auto testObject = baseJson.begin();
        testName = testObject.key();
        testData = testObject.value();
    }

    std::string name() {
        return testName;
    }

    std::string getEnv(const std::string& key) {
        return testData.at("env").at(key);
    }
    bool containsEnv(const std::string& key) {
        return testData.at("env").contains(key);
    }

    // get transaction
    std::vector<ExpectedState> getExpectedStates() {
        std::vector<ExpectedState> expectedStates;

        auto post = testData.at("post");

        for (const auto& postState : post.items()) {
            nlohmann::json data = postState.value();
            const std::string& key = postState.key();
            expectedStates.emplace_back(data, key);
        }

        return expectedStates;
    }

    static evmc::address toEvmcAddress(const std::string& address) {
        evmc::address out;
        if (!address.empty()) {
            auto bytes = silkworm::from_hex(address);
            out = silkworm::to_evmc_address(bytes.value_or(Bytes{}));
        }

        return out;
    }

    // get block
    silkworm::Block getBlock() {
        auto block = silkworm::Block();

        block.header.beneficiary = toEvmcAddress(getEnv("currentCoinbase"));
        block.header.difficulty = intx::from_string<intx::uint256>(getEnv("currentDifficulty"));
        block.header.gas_limit = std::stoull(getEnv("currentGasLimit"), nullptr, /*base=*/16);
        block.header.number = std::stoull(getEnv("currentNumber"), nullptr, /*base=*/16);
        block.header.timestamp = std::stoull(getEnv("currentTimestamp"), nullptr, /*base=*/16);
        block.header.parent_hash = to_bytes32(silkworm::from_hex(getEnv("previousHash")).value_or(silkworm::Bytes{}));

        if (containsEnv("currentRandom")) {
            block.header.mix_hash = to_bytes32(silkworm::from_hex(getEnv("currentRandom")).value_or(silkworm::Bytes{}));
        }

        if (containsEnv("currentBaseFee")) {
            block.header.base_fee_per_gas = intx::from_string<intx::uint256>(getEnv("currentBaseFee"));
        }

        return block;
    }

    std::unique_ptr<silkworm::State> getState() {
        auto state = std::make_unique<silkworm::InMemoryState>();

        auto pre = testData["pre"];

        for (const auto& preState : pre.items()) {
            const auto address = toEvmcAddress(preState.key());
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

    static std::unique_ptr<evmc::address> privateKeyToAddress(const std::string& privateKey) {
        /// Example 1
        // private key: 0x45a915e4d060149eb4365960e6a7a45f334393093061116b197e3240065ff2d8
        // public key : 043a514176466fa815ed481ffad09110a2d344f6c9b78c1d14afc351c3a51be33d8072e77939dc03ba44790779b7a1025baf3003f6732430e20cd9b76d953391b3
        // address    : 0xa94f5374Fce5edBC8E2a8697C15331677e6EbF0B
        /// Example 2
        // private key: 0x227dbb8586117d55284e26620bc76534dfbd2394be34cf4a09cb775d593b6f2b
        // public key : 04aa931f5ee58735270821b3722866d8882d1948909532cf8ac2b3ef144ae8043363d1d3728b49f10c7cd78c38289c8012477473879f3b53169f2a677b7fbed0c7
        // address    : 0xe16C1623c1AA7D919cd2241d8b36d9E79C1Be2A2

        auto private_key = from_hex(privateKey).value();

        silkworm::sentry::common::EccKeyPair pair = silkworm::sentry::common::EccKeyPair(private_key);
        auto public_key_str = pair.public_key().hex();
        const char* public_key_char = public_key_str.c_str();

        uint8_t public_key_bytes[64];
        for (int i = 0; i < 64; i++) {
            sscanf(public_key_char + i * 2, "%2hhx", &public_key_bytes[i]);
        }

        ethash::hash256 hash = ethash::keccak256(public_key_bytes, sizeof(public_key_bytes));

        uint8_t out[20];
        std::memcpy(out, hash.bytes + 12, sizeof(out));

        return std::make_unique<evmc::address>(silkworm::to_evmc_address(out));
    }

    silkworm::Transaction getTransaction(const ExpectedStateTransaction expectedStateTransaction) {
        silkworm::Transaction txn;
        auto jTransaction = testData["transaction"];

        txn.nonce = std::stoull(jTransaction.at("nonce").get<std::string>(), nullptr, 16);
        txn.to = toEvmcAddress(jTransaction.at("to").get<std::string>());
        txn.from = *privateKeyToAddress(jTransaction["secretKey"]);

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

    static void validateTransition(const silkworm::Receipt& /*receipt*/, const ExpectedState& /*state*/) {
        throw std::runtime_error("not implemented");
    }

    void run() {
        for (auto& expectedState : getExpectedStates()) {
            auto config = expectedState.getConfig();
            auto engine = expectedState.getEngine();
            for (const auto& expectedStateTransaction : expectedState.getTransactions()) {
                auto block = getBlock();
                auto state = getState();

                silkworm::ExecutionProcessor processor{block, *engine, *state, config};
                silkworm::Receipt receipt;

                auto txn = getTransaction(expectedStateTransaction);

                processor.execute_transaction(txn, receipt);
                validateTransition(receipt, expectedState);
            }
        }
    }
};
}  // namespace

int main(int argc, char* argv[]) {
    CLI::App app{"Executes Ethereum state transition tests"};
    CLI11_PARSE(app, argc, argv)

    auto stateTransition = new StateTransition("state_transition_sample.json");
    std::cout << stateTransition->name() << std::endl;
    std::cout << stateTransition->getEnv("currentCoinbase") << std::endl;

    try {
        stateTransition->run();
    } catch (const std::exception& e) {
        // code to handle exceptions of type std::exception and its derived classes
        const auto desc = e.what();
        std::cerr << desc << std::endl;
    } catch (int e) {
        // code to handle exceptions of type int
        std::cerr << "An integer exception occurred: " << e << std::endl;
    } catch (...) {
        // code to handle any other type of exception
        std::cerr << "An unknown exception occurred" << std::endl;
    }
    std::cout << "Hello world";
}
