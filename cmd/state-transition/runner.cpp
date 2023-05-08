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

#include <CLI/CLI.hpp>

using namespace silkworm::cmd::state_transition;

int main(int argc, char* argv[]) {
    CLI::App app{"Executes Ethereum state transition tests"};
    CLI11_PARSE(app, argc, argv)

    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != nullptr) {
        std::cout << "Current working directory: " << cwd << std::endl;
    }

    auto stateTransition = new StateTransition("state_transition_sample3.json", false);

    try {
        stateTransition->run();
    } catch (const std::exception& e) {
        // code to handle exceptions of type std::exception and its derived classes
        const auto desc = e.what();
        std::cerr << "Exception: " << desc << std::endl;
    } catch (int e) {
        // code to handle exceptions of type int
        std::cerr << "An integer exception occurred: " << e << std::endl;
    } catch (...) {
        // code to handle any other type of exception
        std::cerr << "An unknown exception occurred" << std::endl;
    }
}
