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
#include <stdexcept>

#include <CLI/CLI.hpp>
#include <nlohmann/json.hpp>

#include <silkworm/core/consensus/engine.hpp>
#include <silkworm/core/execution/execution.hpp>
#include <silkworm/infra/common/directories.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/buffer.hpp>

#include "ExpectedState.hpp"
#include "silkworm/core/state/in_memory_state.hpp"

// #include "state_transition.hpp"

namespace {
class StateTransition {
    nlohmann::json baseJson;

    nlohmann::json testData;
    std::string testName;

  public:
    explicit StateTransition(const std::string& fileName) noexcept {
        std::string basePath = "/home/jacek/dev/silkworm/cmd/";
        std::ifstream input_file(basePath + fileName);
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

    // get transaction
    ExpectedState getExpectedState() {
        auto expectedState = testData.at("post").begin();
        nlohmann::json data = expectedState.value();
        const std::string& key = expectedState.key();
        return ExpectedState(data, key);
    }

    silkworm::Transaction getTransaction() {
        return silkworm::Transaction();
    }

    // get block
    silkworm::Block getBlock() {
        auto block = testData.at("pre").at("block");
        return silkworm::Block();
    }

    void setInitialState(silkworm::InMemoryState* /*pState*/) {

        for (auto it = testData.at("pre").begin(); it != testData.at("pre").end(); ++it) {
            auto key = it.key();
            auto value = it.value();
            if (key == "block") {
                continue;
            }
            auto address = silkworm::from_hex(key);
//            auto account = silkworm::Account();
//
//            account.balance = 0;
//            pState->update_account(address, account, tr);
//            pState->update_account_code(address, account);
//            pState->update_storage(address, account);
        }
    }

    silkworm::State* getState() {
        auto state = new silkworm::InMemoryState();

        setInitialState(state);

        return state;
    }

    void validateTransation(silkworm::Receipt /*receipt*/, ExpectedState /*state*/) {
        throw "not implemented";
    }

    void run() {
        auto expectedState = getExpectedState();
        auto block = getBlock();
        auto state = getState();
        auto engine = expectedState.getEngine();

        silkworm::ExecutionProcessor processor{block, *engine, *state, expectedState.getConfig()};

        silkworm::Receipt receipt;
        auto txn = getTransaction();
        processor.execute_transaction(txn, receipt);

        validateTransation(receipt, expectedState);
    }

    //    void run()  {
    //        silkworm::ExecutionProcessor processor{block, *engine, buffer, *chain_config};
    //    }
};
}  // namespace

int main(int argc, char* argv[]) {
    CLI::App app{"Executes Ethereum state transition tests"};
    using namespace silkworm;
    CLI11_PARSE(app, argc, argv);

    auto stateTransition = new StateTransition("state_transition_sample.json");
    std::cout << stateTransition->name() << std::endl;
    std::cout << stateTransition->getEnv("currentCoinbase") << std::endl;

    std::cout << "Hello world";
}
