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

#include "wait_strategy.hpp"

#include <atomic>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

#include <catch2/catch.hpp>
#include <grpcpp/grpcpp.h>

using namespace std::chrono_literals;  // NOLINT(build/namespaces)

namespace silkworm::rpc {

using Catch::Matchers::Message;

TEST_CASE("parse wait mode", "[silkrpc][common][log]") {
    std::vector<absl::string_view> input_texts{
        "backoff", "blocking", "sleeping", "yielding", "busy_spin"};
    std::vector<WaitMode> expected_wait_modes{
        WaitMode::backoff,
        WaitMode::blocking,
        WaitMode::sleeping,
        WaitMode::yielding,
        WaitMode::busy_spin,
    };
    for (std::size_t i{0}; i < input_texts.size(); i++) {
        WaitMode wait_mode;
        std::string error;
        const auto success{AbslParseFlag(input_texts[i], &wait_mode, &error)};
        CHECK(success == true);
        CHECK(error.empty());
        CHECK(wait_mode == expected_wait_modes[i]);
    }
}

TEST_CASE("parse invalid wait mode", "[silkrpc][common][log]") {
    WaitMode wait_mode;
    std::string error;
    const auto success{AbslParseFlag("abc", &wait_mode, &error)};
    CHECK(success == false);
    CHECK(!error.empty());
}

TEST_CASE("unparse wait mode", "[silkrpc][common][log]") {
    std::vector<WaitMode> input_wait_modes{
        WaitMode::backoff,
        WaitMode::blocking,
        WaitMode::sleeping,
        WaitMode::yielding,
        WaitMode::busy_spin,
    };
    std::vector<absl::string_view> expected_texts{
        "backoff", "blocking", "sleeping", "yielding", "busy_spin"};
    for (std::size_t i{0}; i < input_wait_modes.size(); i++) {
        const auto text{AbslUnparseFlag(input_wait_modes[i])};
        CHECK(text == expected_texts[i]);
    }
}

template <typename W, typename R, typename P>
inline void sleep_then_check_wait(W& w, const std::chrono::duration<R, P>& t, int executed_count) {
    std::this_thread::sleep_for(t);
    CHECK_NOTHROW(w.idle(executed_count));
}

TEST_CASE("SleepingWaitStrategy", "[silkrpc][context_pool]") {
    SleepingWaitStrategy wait_strategy{1ms};
    sleep_then_check_wait(wait_strategy, 10ms, 1);
    sleep_then_check_wait(wait_strategy, 20ms, 0);
    sleep_then_check_wait(wait_strategy, 20ms, 0);
    sleep_then_check_wait(wait_strategy, 10ms, 1);
}

TEST_CASE("YieldingWaitStrategy", "[silkrpc][context_pool]") {
    YieldingWaitStrategy wait_strategy;
    sleep_then_check_wait(wait_strategy, 10ms, 1);
    sleep_then_check_wait(wait_strategy, 20ms, 0);
    sleep_then_check_wait(wait_strategy, 20ms, 0);
    sleep_then_check_wait(wait_strategy, 10ms, 1);
}

TEST_CASE("BusySpinWaitStrategy", "[silkrpc][context_pool]") {
    BusySpinWaitStrategy wait_strategy;
    sleep_then_check_wait(wait_strategy, 10ms, 1);
    sleep_then_check_wait(wait_strategy, 20ms, 0);
    sleep_then_check_wait(wait_strategy, 20ms, 0);
    sleep_then_check_wait(wait_strategy, 10ms, 1);
}

}  // namespace silkworm::rpc
