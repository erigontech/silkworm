/*
   Copyright 2024 The Silkworm Authors

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

#include "async_task.hpp"

#include <string>
#include <vector>

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch.hpp>

#include <silkworm/rpc/test_util/context_test_base.hpp>

namespace silkworm::rpc {

struct AsyncTaskTest : test::ContextTestBase {
};

const static std::vector<std::pair<std::size_t, std::size_t>> kTestData = {
    {0, 1},
    {1, 1},
    {9, 362'880},
    {10, 3'628'800},
};

std::size_t recursive_factorial(std::size_t n) {
    return n == 0 ? 1 : n * recursive_factorial(n - 1);
}

template <typename Executor>
Task<std::size_t> async_factorial(Executor runner, std::size_t number) {
    co_return co_await async_task(runner, recursive_factorial, number);
}

TEST_CASE_METHOD(AsyncTaskTest, "async_task: factorial", "[rpc][common][async_task]") {
    boost::asio::thread_pool workers;
    for (std::size_t i{0}; i < kTestData.size(); ++i) {
        const auto [n, r] = kTestData[i];
        SECTION("factorial " + std::to_string(n)) {
            CHECK(spawn_and_wait(async_factorial(workers.get_executor(), n)) == r);
            CHECK(spawn_and_wait(async_task(workers.get_executor(), recursive_factorial, n)) == r);
        }
    }
}

void raise_exception() {
    throw std::runtime_error{""};
}

void raise_exception_with_args(int i) {
    if (i > 0) {
        throw std::runtime_error{""};
    }
}

template <typename Executor>
Task<void> async_raise_exception(Executor runner) {
    co_await async_task(runner, raise_exception);
    co_return;
}

template <typename Executor>
Task<void> async_raise_exception_with_args(Executor runner, int i) {
    co_await async_task(runner, raise_exception_with_args, i);
    co_return;
}

template <typename Executor>
Task<void> async_lambda_raise_exception(Executor runner) {
    co_await async_task(runner, []() { throw std::runtime_error{""}; });
    co_return;
}

template <typename Executor>
Task<void> async_lambda_raise_exception_with_args(Executor runner, int i) {
    co_await async_task(
        runner, [](auto ii) { if (ii > 0) throw std::runtime_error{""}; }, i);
    co_return;
}

TEST_CASE_METHOD(AsyncTaskTest, "async_task: exception", "[rpc][common][async_task]") {
    boost::asio::thread_pool workers;
    CHECK_THROWS_AS(spawn_and_wait(async_task(workers.get_executor(), raise_exception)), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_raise_exception(workers.get_executor())), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_lambda_raise_exception(workers.get_executor())), std::runtime_error);

    CHECK_THROWS_AS(spawn_and_wait(async_task(workers.get_executor(), raise_exception_with_args, 1)), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_raise_exception_with_args(workers.get_executor(), 1)), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_lambda_raise_exception_with_args(workers.get_executor(), 1)), std::runtime_error);
}

}  // namespace silkworm::rpc
