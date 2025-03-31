// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <csignal>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/signal_handler.hpp>

namespace silkworm {

#if !defined(__APPLE__) || defined(NDEBUG)
static const std::vector<int> kSignalNumbers{SIGINT, SIGTERM};

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
