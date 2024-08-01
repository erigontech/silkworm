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

#include <benchmark/benchmark.h>

#include <silkworm/infra/test_util/context_test_base.hpp>

#include "paginated_sequence.hpp"

namespace silkworm::db::kv::api {

using PaginatedUint64 = PaginatedSequence<uint64_t>;

struct PaginatedSequenceBenchTest : public test_util::ContextTestBase {
};

template <typename TSequence>
TSequence make_paginated_sequence(const std::size_t page_size, const std::size_t n) {
    const std::size_t num_pages = n / page_size + (n % page_size ? 1 : 0);
    const std::size_t last_page_size = n % page_size ? n % page_size : page_size;
    typename TSequence::Paginator paginator = [=]() -> Task<typename TSequence::PageResult> {
        static std::size_t count{0};
        const bool has_more = ++count < num_pages;
        typename TSequence::Page p(has_more ? page_size : last_page_size, 0);
        co_return typename TSequence::PageResult{std::move(p), has_more};
    };
    return TSequence{std::move(paginator)};
}

Task<std::size_t> paginated_sequence_iteration(PaginatedUint64& paginated) {
    std::size_t accumulator{0};
    auto it = co_await paginated.begin();
    while (it != paginated.end()) {
        accumulator += *it;
        co_await ++it;
    }
    co_return accumulator;
}

static void benchmark_paginated_sequence_iteration(benchmark::State& state) {
    const auto page_size = static_cast<std::size_t>(state.range(0));
    const auto n = static_cast<std::size_t>(state.range(1));

    PaginatedSequenceBenchTest test;
    auto paginated_sequence = make_paginated_sequence<PaginatedUint64>(page_size, n);
    for ([[maybe_unused]] auto _ : state) {
        const auto result = test.spawn_and_wait(paginated_sequence_iteration(paginated_sequence));
        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(benchmark_paginated_sequence_iteration)->Args({100, 1'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({100, 10'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({100, 100'001});

BENCHMARK(benchmark_paginated_sequence_iteration)->Args({1'000, 1'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({1'000, 10'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({1'000, 100'001});

BENCHMARK(benchmark_paginated_sequence_iteration)->Args({10'000, 10'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({10'000, 100'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({10'000, 1'000'001});

BENCHMARK(benchmark_paginated_sequence_iteration)->Args({100'000, 100'001});
BENCHMARK(benchmark_paginated_sequence_iteration)->Args({100'000, 1'000'001});

// Modified version of PaginatedSequence to check performance tradeoffs w/ different impl
// - PaginatedSequence: async operator++ (more convenient at call site)
// - PaginatedSequence2: sync operator++ plus async next_page
template <typename T>
class PaginatedSequence2 {
  public:
    using Page = std::vector<T>;
    struct PageResult {
        Page values;
        bool has_more{false};
    };
    using Paginator = std::function<Task<PageResult>()>;

    class Iterator {
      public:
        T operator*() {
            return std::move(*it_);
        }

        bool operator++() {
            ++it_;
            if (it_ == current_.values.cend()) {
                if (current_.has_more) {
                    return true;
                } else {
                    it_ = typename Page::const_iterator();  // empty i.e. sentinel value
                }
            }
            return false;
        }

        Task<void> next_page() {
            current_ = co_await next_page_provider_();
            it_ = current_.values.cbegin();
        }

        bool operator==(const Iterator& other) const noexcept {
            return it_ == other.it_;
        }

        bool operator!=(const Iterator& other) const noexcept {
            return !(*this == other);
        }

        Iterator(Paginator& next_page_provider, PageResult current) noexcept
            : next_page_provider_(next_page_provider), current_(std::move(current)), it_{current_.values.cbegin()} {}
        explicit Iterator(Paginator& next_page_provider) noexcept
            : next_page_provider_(next_page_provider) {}

      private:
        Paginator& next_page_provider_;
        PageResult current_;
        typename Page::const_iterator it_;  // empty i.e. sentinel value
    };

    explicit PaginatedSequence2(Paginator next_page_provider) noexcept
        : next_page_provider_(std::move(next_page_provider)) {}

    Task<Iterator> begin() {
        auto current = co_await next_page_provider_();
        co_return Iterator{next_page_provider_, std::move(current)};
    }

    Iterator end() noexcept {
        return Iterator{next_page_provider_};
    }

  private:
    Paginator next_page_provider_;
};

using Paginated2Uint64 = PaginatedSequence2<uint64_t>;

Task<std::size_t> paginated_sequence_2_iteration(Paginated2Uint64& paginated) {
    std::size_t accumulator{0};
    auto it = co_await paginated.begin();
    while (it != paginated.end()) {
        accumulator += *it;
        const bool next_page = ++it;
        if (next_page) {
            co_await it.next_page();
        }
    }
    co_return accumulator;
}

static void benchmark_paginated_sequence_2_iteration(benchmark::State& state) {
    const auto page_size = static_cast<std::size_t>(state.range(0));
    const auto n = static_cast<std::size_t>(state.range(1));

    PaginatedSequenceBenchTest test;
    auto paginated_sequence = make_paginated_sequence<Paginated2Uint64>(page_size, n);
    for ([[maybe_unused]] auto _ : state) {
        const auto result = test.spawn_and_wait(paginated_sequence_2_iteration(paginated_sequence));
        benchmark::DoNotOptimize(result);
    }
}

BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({100, 1'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({100, 10'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({100, 100'001});

BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({1'000, 1'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({1'000, 10'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({1'000, 100'001});

BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({10'000, 10'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({10'000, 100'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({10'000, 1'000'001});

BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({100'000, 100'001});
BENCHMARK(benchmark_paginated_sequence_2_iteration)->Args({100'000, 1'000'001});

}  // namespace silkworm::db::kv::api
