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

#include <boost/asio/thread_pool.hpp>
#include <benchmark/benchmark.h>

#include <silkworm/rpc/test/context_test_base.hpp>

namespace silkworm::rpc {

std::size_t recursive_factorial(std::size_t n) {
    return n == 0 ? 1 : n * recursive_factorial(n - 1);
}

struct AsyncTaskBenchTest : test::ContextTestBase {
};

template <typename Executor>
Task<std::size_t> async_compose_factorial(const Executor runner, const std::size_t number) {
    const auto this_executor = co_await ThisTask::executor;
    co_return co_await boost::asio::async_compose<decltype(boost::asio::use_awaitable), void(std::exception_ptr, std::size_t)>(
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
    const auto n = static_cast<std::size_t>(state.range(0));

    boost::asio::thread_pool workers{};
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
Task<std::size_t> async_task_factorial(Executor runner, std::size_t number) {
    co_return co_await async_task(runner, recursive_factorial, number);
}

static void benchmark_async_task(benchmark::State& state) {
    const auto n = static_cast<std::size_t>(state.range(0));

    boost::asio::thread_pool workers{};
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
