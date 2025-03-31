// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "timer.hpp"

#include <array>
#include <string>
#include <thread>

#include <boost/asio/io_context.hpp>
#include <catch2/catch_test_macros.hpp>

namespace silkworm {

struct TimerTest {
    static constexpr std::array<uint32_t, 3> kIntervals{100, 10, 1};  // milliseconds
    boost::asio::io_context ioc;
};

TEST_CASE_METHOD(TimerTest, "Periodic timer", "[infra][common][timer]") {
    static constexpr size_t kExpectedExpirations{2};
    size_t expired_count{0};  // The lambda capture-list content *must* outlive the scheduler execution loop
    for (const auto interval : kIntervals) {
        Timer periodic_timer{
            ioc.get_executor(),
            interval,
            [&]() -> bool {
                ++expired_count;
                // Stop the timer scheduler after multiple expirations
                if (expired_count == kExpectedExpirations) {
                    ioc.stop();
                }
                return true;
            },
        };
        SECTION("Duration " + std::to_string(interval) + "ms : expired") {
            ioc.run();  // run until timer expires, then the callback will stop us
        }
        SECTION("Duration " + std::to_string(interval) + "ms : cancelled") {
            periodic_timer.stop();
            ioc.run();
            // may be expired multiple times or not depending on interval
        }
        SECTION("Duration " + std::to_string(interval) + "ms : rescheduled") {
            periodic_timer.reset();
            ioc.run();
            // may be expired multiple times or not depending on interval
        }
        expired_count = 0;
    }
}

TEST_CASE_METHOD(TimerTest, "One shot timer", "[infra][common][timer]") {
    bool timer_expired{false};  // The lambda capture-list content *must* outlive the scheduler execution loop
    for (const auto interval : kIntervals) {
        Timer one_shot_timer{
            ioc.get_executor(),
            interval,
            [&]() -> bool {
                ioc.stop();
                timer_expired = true;
                return true;
            },
        };
        SECTION("Duration " + std::to_string(interval) + "ms: expired") {
            ioc.run();  // run until timer expires, then the callback will stop us
            CHECK(timer_expired);
        }
        SECTION("Duration " + std::to_string(interval) + "ms: cancelled") {
            one_shot_timer.stop();
            ioc.run();
            // may be expired or not depending on interval
        }
        SECTION("Duration " + std::to_string(interval) + "ms: rescheduled") {
            one_shot_timer.reset();
            ioc.run();
            // may be expired or not depending on interval
        }
        timer_expired = false;
    }
}

TEST_CASE_METHOD(TimerTest, "Cancellation before expiration", "[infra][common][timer]") {
    bool timer_expired{false};  // The lambda capture-list content *must* outlive the scheduler execution loop
    for (const auto interval : kIntervals) {
        SECTION("Duration " + std::to_string(interval) + "ms") {
            Timer async_timer{
                ioc.get_executor(),
                interval,
                [&]() -> bool {
                    timer_expired = true;
                    return true;
                },
                /*auto_start=*/true,
            };
            async_timer.stop();
            CHECK_NOTHROW(ioc.run());
            CHECK(!timer_expired);
        }
        timer_expired = false;
    }
}

TEST_CASE_METHOD(TimerTest, "Lifecycle race condition", "[infra][common][timer]") {
    for (const auto interval : kIntervals) {
        SECTION("Duration " + std::to_string(interval) + "ms") {
            {
                Timer async_timer{ioc.get_executor(), interval, []() -> bool { return true; }};
                async_timer.start();
                ioc.poll();  // serve just one task
                async_timer.stop();
            }  // timer gets deleted here or after callback dispatch
            CHECK_NOTHROW(ioc.run());
        }
    }
}

TEST_CASE_METHOD(TimerTest, "Explicit stop not necessary", "[infra][common][timer]") {
    for (const auto interval : kIntervals) {
        SECTION("Duration " + std::to_string(interval) + "ms: stopped") {
            {
                Timer async_timer{ioc.get_executor(), interval, []() -> bool { return true; }};
                async_timer.stop();
            }
            // The timer has been stopped explicitly: the scheduler eventually runs out of work
            const auto executed_handlers = ioc.run();  // serve all remaining tasks
            CHECK(executed_handlers > 0);
        }
        SECTION("Duration " + std::to_string(interval) + "ms: not stopped") {
            {
                Timer async_timer{ioc.get_executor(), interval, []() -> bool { return true; }};
            }
            // The timer has *not* been stopped explicitly, but automatically: the scheduler eventually runs out of work anyway
            const auto executed_handlers = ioc.run();  // serve all remaining tasks
            CHECK(executed_handlers > 0);
        }
    }
}

}  // namespace silkworm
