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

#include <chrono>
#include <stdexcept>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/concurrency/awaitable_wait_for_all.hpp>
#include <silkworm/infra/concurrency/co_spawn_sw.hpp>

using namespace boost::asio;
using namespace boost::asio::experimental;
using namespace silkworm::concurrency;
using namespace std::chrono_literals;

awaitable<void> my_sleep(std::chrono::milliseconds duration) {
    auto executor = co_await this_coro::executor;
    steady_timer timer(executor);
    timer.expires_after(duration);
    co_await timer.async_wait(use_awaitable);
}

awaitable<void> noop() {
    co_return;
}

awaitable<void> throw_op() {
    co_await my_sleep(1ms);
    throw std::runtime_error("throw_op");
}

awaitable<void> spawn_throw_op(strand<any_io_executor>& strand) {
    co_await co_spawn_sw(strand, throw_op(), use_awaitable);
}

awaitable<void> spawn_noop_loop(strand<any_io_executor>& strand) {
    while (true) {
        co_await co_spawn_sw(strand, noop(), use_awaitable);
    }
}

awaitable<void> co_spawn_cancellation_handler_bug() {
    using namespace awaitable_wait_for_all;
    auto executor = co_await boost::asio::this_coro::executor;
    auto strand = make_strand(executor);

    try {
        co_await (my_sleep(1s) && spawn_throw_op(strand) && spawn_noop_loop(strand));
    } catch (std::runtime_error&) {
    }
}

TEST_CASE("parallel_group.co_spawn_cancellation_handler_bug") {
    io_context context;
    auto run_future = co_spawn_sw(context, co_spawn_cancellation_handler_bug(), use_future);
    context.run();
}
