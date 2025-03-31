// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "async_task.hpp"

#include <string>
#include <vector>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>

namespace silkworm::rpc {

struct AsyncTaskTest : test_util::ServiceContextTestBase {
};

static const std::vector<std::pair<size_t, size_t>> kTestData{
    {0, 1},
    {1, 1},
    {9, 362'880},
    {10, 3'628'800},
};

size_t recursive_factorial(size_t n) {
    return n == 0 ? 1 : n * recursive_factorial(n - 1);
}

template <typename Executor>
Task<size_t> async_factorial(Executor runner, size_t number) {
    co_return co_await async_task(runner, recursive_factorial, number);
}

TEST_CASE_METHOD(AsyncTaskTest, "async_task: factorial", "[rpc][common][async_task]") {
    WorkerPool workers;
    for (size_t i{0}; i < kTestData.size(); ++i) {
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
    WorkerPool workers;
    CHECK_THROWS_AS(spawn_and_wait(async_task(workers.get_executor(), raise_exception)), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_raise_exception(workers.get_executor())), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_lambda_raise_exception(workers.get_executor())), std::runtime_error);

    CHECK_THROWS_AS(spawn_and_wait(async_task(workers.get_executor(), raise_exception_with_args, 1)), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_raise_exception_with_args(workers.get_executor(), 1)), std::runtime_error);
    CHECK_THROWS_AS(spawn_and_wait(async_lambda_raise_exception_with_args(workers.get_executor(), 1)), std::runtime_error);
}

}  // namespace silkworm::rpc
