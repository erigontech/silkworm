// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <benchmark/benchmark.h>

#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>

#include "async_task.hpp"

namespace silkworm::rpc {

size_t recursive_factorial(size_t n) {
    return n == 0 ? 1 : n * recursive_factorial(n - 1);
}

struct AsyncTaskBenchTest : test_util::ServiceContextTestBase {
};

template <typename Executor>
Task<size_t> async_compose_factorial(const Executor runner, const size_t number) {
    const auto this_executor = co_await boost::asio::this_coro::executor;
    co_return co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::exception_ptr, size_t)>(
        [&](auto& self) {
            boost::asio::post(runner, [&, self = std::move(self)]() mutable {
                try {
                    const auto result = recursive_factorial(number);
                    boost::asio::post(this_executor, [result, self = std::move(self)]() mutable {
                        self.complete({}, result);
                    });
                } catch (...) {
                    std::exception_ptr eptr = std::current_exception();
                    boost::asio::post(this_executor, [eptr, self = std::move(self)]() mutable {
                        self.complete(eptr, {});
                    });
                }
            });
        },
        boost::asio::use_awaitable);
}

static void benchmark_async_compose(benchmark::State& state) {
    const auto n = static_cast<size_t>(state.range(0));

    WorkerPool workers{};
    AsyncTaskBenchTest test;
    for ([[maybe_unused]] auto _ : state) {
        const auto result = test.spawn_and_wait(async_compose_factorial(workers.get_executor(), n));
        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(benchmark_async_compose)->Arg(10);
BENCHMARK(benchmark_async_compose)->Arg(100);
BENCHMARK(benchmark_async_compose)->Arg(1'000);
BENCHMARK(benchmark_async_compose)->Arg(10'000);

template <typename Executor>
Task<size_t> async_task_factorial(Executor runner, size_t number) {
    co_return co_await async_task(runner, recursive_factorial, number);
}

static void benchmark_async_task(benchmark::State& state) {
    const auto n = static_cast<size_t>(state.range(0));

    WorkerPool workers{};
    AsyncTaskBenchTest test;
    for ([[maybe_unused]] auto _ : state) {
        const auto result = test.spawn_and_wait(async_task_factorial(workers.get_executor(), n));
        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(benchmark_async_task)->Arg(10);
BENCHMARK(benchmark_async_task)->Arg(100);
BENCHMARK(benchmark_async_task)->Arg(1'000);
BENCHMARK(benchmark_async_task)->Arg(10'000);

}  // namespace silkworm::rpc
