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

#include <csignal>

#include <catch2/catch.hpp>

#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm {

#if !defined(__APPLE__) || defined(NDEBUG)
constexpr std::array kSignalNumbers{SIGINT, SIGTERM};

TEST_CASE("SignalHandler") {
    for (const auto sig_number : kSignalNumbers) {
        SECTION("signal number: " + std::to_string(sig_number)) {
            SignalHandler::init({}, /*silent=*/true);
            REQUIRE(std::raise(sig_number) == 0);
            CHECK(SignalHandler::signalled());
            SignalHandler::reset();
            CHECK_FALSE(SignalHandler::signalled());
        }
    }
}

TEST_CASE("SignalHandler: custom handler") {
    for (const auto sig_number : kSignalNumbers) {
        SECTION("signal number: " + std::to_string(sig_number)) {
            auto custom_handler = [sig_number](int sig_code) {
                CHECK(sig_code == sig_number);
            };
            SignalHandler::init(custom_handler, /*silent=*/true);
            REQUIRE(std::raise(sig_number) == 0);
            CHECK(SignalHandler::signalled());
            SignalHandler::reset();
            CHECK_FALSE(SignalHandler::signalled());
        }
    }
}
#endif  // !defined(__APPLE__) || defined(NDEBUG)

}  // namespace silkworm
