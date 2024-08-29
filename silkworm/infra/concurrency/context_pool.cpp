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

#include "context_pool.hpp"

#include <thread>
#include <utility>

#include <boost/asio/post.hpp>
#include <boost/asio/thread_pool.hpp>
#include <magic_enum.hpp>

namespace silkworm::concurrency {

std::ostream& operator<<(std::ostream& out, const Context& c) {
    out << "io_context: " << c.io_context() << " wait_mode: " << magic_enum::enum_name(c.wait_mode());
    return out;
}

Context::Context(std::size_t context_id, WaitMode wait_mode)
    : context_id_(context_id),
      io_context_{std::make_shared<boost::asio::io_context>()},
      work_{boost::asio::make_work_guard(*io_context_)},
      wait_mode_(wait_mode) {}

void Context::execute_loop() {
    switch (wait_mode_) {
        case WaitMode::backoff:
            execute_loop_single_threaded(YieldingIdleStrategy{});  // TODO(canepat) replace with BackOffIdleStrategy
            break;
        case WaitMode::blocking:
            execute_loop_multi_threaded();
            break;
        case WaitMode::yielding:
            execute_loop_single_threaded(YieldingIdleStrategy{});
            break;
        case WaitMode::sleeping:
            execute_loop_single_threaded(SleepingIdleStrategy{});
            break;
        case WaitMode::busy_spin:
            execute_loop_single_threaded(BusySpinIdleStrategy{});
            break;
    }
}

void Context::stop() {
    io_context_->stop();
}

template <typename IdleStrategy>
void Context::execute_loop_single_threaded(IdleStrategy idle_strategy) {
    SILK_DEBUG << "Single-thread execution loop start [" << std::this_thread::get_id() << "]";
    while (!io_context_->stopped()) {
        std::size_t work_count = io_context_->poll();
        idle_strategy.idle(work_count);
    }
    SILK_DEBUG << "Single-thread execution loop end [" << std::this_thread::get_id() << "]";
}

void Context::execute_loop_multi_threaded() {
    SILK_DEBUG << "Multi-thread execution loop start [" << std::this_thread::get_id() << "]";
    const auto num_threads = std::thread::hardware_concurrency() / 2;
    boost::asio::thread_pool pool{num_threads};
    for (std::size_t i{0}; i < num_threads; ++i) {
        boost::asio::post(pool, [&]() { io_context_->run(); });
    }
    pool.join();
    SILK_DEBUG << "Multi-thread execution loop end [" << std::this_thread::get_id() << "]";
}

}  // namespace silkworm::concurrency
