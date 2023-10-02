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

#include <deque>
#include <list>

#include <benchmark/benchmark.h>

#include <silkworm/node/etl/buffer.hpp>

namespace silkworm::etl {

// A buffer that uses std::list
// Benchmarks show that it is slower than std::vector except for some cases

class ListBuffer {
  public:
    // Not copyable nor movable
    ListBuffer(const ListBuffer&) = delete;
    ListBuffer& operator=(const ListBuffer&) = delete;

    explicit ListBuffer(size_t optimal_size) : optimal_size_(optimal_size) {}

    void put(const Entry& entry) {
        // Add a new entry to the buffer
        size_ += entry.size() + sizeof(head_t);
        buffer_.push_back(entry);
    }

    void put(Entry&& entry) {
        // Add a new entry to the buffer
        size_ += entry.size() + sizeof(head_t);
        buffer_.push_back(std::move(entry));
    }

    void clear() noexcept {
        // Set the buffer to contain 0 entries
        buffer_.clear();
        size_ = 0;
    }

    [[nodiscard]] bool overflows() const noexcept {
        // Whether accounted size overflows optimal_size_ (i.e. time to flush)
        return size_ >= optimal_size_;
    }

    void sort() {
        // Sort buffer in increasing order by key comparison
        buffer_.sort();
    }

    [[nodiscard]] size_t size() const noexcept {
        // Actual size of accounted data
        return size_;
    }

    [[nodiscard]] const std::list<Entry>& entries() const noexcept { return buffer_; }

  private:
    size_t optimal_size_;
    size_t size_ = 0;

    std::list<Entry> buffer_;  // buffer for holding entries
};

}  // namespace silkworm::etl

template <typename BUFFER>
void fill(BUFFER& buffer, int64_t num_of_entries, int64_t entry_size) {
    for (int i = 0; i < num_of_entries; i++) {
        silkworm::Bytes key(size_t(entry_size / 2), uint8_t(256 - i % 256));
        silkworm::Bytes value(size_t(entry_size / 2), uint8_t(i % 256));

        silkworm::etl::Entry entry{key, value};
        buffer.put(std::move(entry));
    }
}

// vector buffer
static void BM_VectorBuffer(benchmark::State& state) {
    for (auto _ : state) {
        silkworm::etl::Buffer buffer(size_t(state.range(0)));
        fill(buffer, state.range(0), state.range(1));
        buffer.sort();
    }
}

/*
// list buffer, this is slower except some cases
static void BM_ListBuffer(benchmark::State& state) {
    for (auto _ : state) {
        silkworm::etl::ListBuffer buffer(100'000);
        fill(buffer, state.range(0), state.range(1));
        buffer.sort();
    }
}
*/

BENCHMARK(BM_VectorBuffer)
    ->Unit(benchmark::kMillisecond)
    ->Ranges({
        {128, 1024 * 1024},  // number_of_entries
        {128, 4096}          // entry_size
    });

/*
BENCHMARK(BM_ListBuffer)
    ->Unit(benchmark::kMillisecond)
    ->Ranges({
        {128, 1024*1024}, // number_of_entries
        {128, 4096}   // entry_size
    });
*/

// Run with --benchmark_filter=BM_VectorBuffer|BM_ListBuffer --benchmark_out_format=json --benchmark_out=buffer_benchmark.json
