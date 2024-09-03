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

#include "timer.hpp"

#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm {

struct TimerTest {
    const std::vector<uint32_t> kIntervals{100, 10, 1};  // milliseconds
    boost::asio::io_context io_context;
};

TEST_CASE_METHOD(TimerTest, "Periodic timer", "[infra][common][timer]") {
    constexpr static size_t kExpectedExpirations{2};
    size_t expired_count{0};  // The lambda capture-list content *must* outlive the scheduler execution loop
    for (const auto interval : kIntervals) {
        auto periodic_timer = Timer::create(io_context.get_executor(), interval, [&]() -> bool {
            ++expired_count;
            if (expired_count == kExpectedExpirations) {  // stop timer scheduler after multiple expirations
                io_context.stop();
            }
            return true;
        });
        SECTION("Duration " + std::to_string(interval) + "ms : expired") {
            io_context.run();  // run until timer expires, then the callback will stop us
        }
        SECTION("Duration " + std::to_string(interval) + "ms : cancelled") {
            periodic_timer->stop();
            io_context.run();
            // may be expired multiple times or not depending on interval
        }
        SECTION("Duration " + std::to_string(interval) + "ms : rescheduled") {
            periodic_timer->reset();
            io_context.run();
            // may be expired multiple times or not depending on interval
        }
        expired_count = 0;
    }
}

TEST_CASE_METHOD(TimerTest, "One shot timer", "[infra][common][timer]") {
    bool timer_expired{false};  // The lambda capture-list content *must* outlive the scheduler execution loop
    for (const auto interval : kIntervals) {
        auto one_shot_timer = Timer::create(io_context.get_executor(), interval, [&]() -> bool {
            io_context.stop();
            timer_expired = true;
            return true;
        });
        SECTION("Duration " + std::to_string(interval) + "ms : expired") {
            io_context.run();  // run until timer expires, then the callback will stop us
            CHECK(timer_expired);
        }
        SECTION("Duration " + std::to_string(interval) + "ms : cancelled") {
            one_shot_timer->stop();
            io_context.run();
            // may be expired or not depending on interval
        }
        SECTION("Duration " + std::to_string(interval) + "ms : rescheduled") {
            one_shot_timer->reset();
            io_context.run();
            // may be expired or not depending on interval
        }
        timer_expired = false;
    }
}

TEST_CASE_METHOD(TimerTest, "Cancellation before expiration", "[infra][common][timer]") {
    bool timer_expired{false};  // The lambda capture-list content *must* outlive the scheduler execution loop
    for (const auto interval : kIntervals) {
        SECTION("Duration " + std::to_string(interval) + "ms") {
            auto async_timer = Timer::create(
                io_context.get_executor(), interval, [&]() -> bool {
                    timer_expired = true;
                    return true;
                },
                /*auto_start=*/true);
            async_timer->stop();
            CHECK_NOTHROW(io_context.run());
            CHECK(!timer_expired);
        }
        timer_expired = false;
    }
}

TEST_CASE_METHOD(TimerTest, "Lifecycle race condition", "[infra][common][timer]") {
    for (const auto interval : kIntervals) {
        SECTION("Duration " + std::to_string(interval) + "ms") {
            {
                auto async_timer = Timer::create(io_context.get_executor(), interval, []() -> bool { return true; });
                async_timer->start();
                io_context.poll();  // serve just one task
                async_timer->stop();
            }  // timer gets deleted here or after callback dispatch
            CHECK_NOTHROW(io_context.run());
        }
    }
}

}  // namespace silkworm
