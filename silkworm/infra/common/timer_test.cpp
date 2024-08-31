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

TEST_CASE("Timer lifecycle race condition") {
    struct TimerInfo {
        std::string description;
        uint32_t interval;
    };
    const std::vector<TimerInfo> timer_infos{
        {"long_running_timer", 10'000},
        {"short_running_timer", 100},
        {"very_short_running_timer", 10},
    };
    boost::asio::io_context io_context;
    for (const auto& [description, interval] : timer_infos) {
        bool timer_expired{false};
        SECTION(description) {
            {
                auto async_timer = Timer::create(io_context.get_executor(), interval, [&timer_expired]() -> bool {
                    timer_expired = true;
                    return timer_expired;
                });
                async_timer->start();
                io_context.poll();  // serve just one task
                async_timer->stop();
            }
            CHECK_NOTHROW(io_context.run());
        }
    }
}

}  // namespace silkworm
