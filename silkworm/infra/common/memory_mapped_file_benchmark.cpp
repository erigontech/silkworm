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

#include <filesystem>
#include <fstream>
#include <utility>

#include <benchmark/benchmark.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/random_number.hpp>
#include <silkworm/infra/common/directories.hpp>

#include "memory_mapped_file.hpp"

constexpr uint64_t k4MiBFileSize{4u * silkworm::kMebi};

static inline std::filesystem::path create_random_temporary_file(int64_t file_size) {
    auto tmp_file = silkworm::TemporaryDirectory::get_unique_temporary_path();
    std::ofstream tmp_stream{tmp_file, std::ios_base::binary};
    silkworm::RandomNumber rnd{0, 255};
    for (int64_t i{0u}; i < file_size; ++i) {
        const auto random_number = static_cast<char>(rnd.generate_one());
        tmp_stream.write(&random_number, sizeof(char));
    }
    tmp_stream.close();
    return tmp_file;
}

static void benchmark_checksum_ifstream(benchmark::State& state) {
    constexpr int kPageSize{1024 * 4};
    const auto tmp_file_path = create_random_temporary_file(state.range(0));

    for ([[maybe_unused]] auto _ : state) {
        std::unique_ptr<char[]> buffer{new char[static_cast<size_t>(kPageSize)]};
        std::ifstream snapshot_stream{tmp_file_path, std::ifstream::binary};
        int checksum{0};
        size_t count{0};
        while (snapshot_stream) {
            snapshot_stream.read(buffer.get(), kPageSize);
            for (size_t i{0}; std::cmp_less(i, snapshot_stream.gcount()); ++i, ++count) {
                const auto byte{static_cast<unsigned char>(buffer[i])};
                checksum += byte;
            }
        }
        benchmark::DoNotOptimize(checksum);
    }
}

BENCHMARK(benchmark_checksum_ifstream)->Arg(k4MiBFileSize);

static void benchmark_checksum_memory_mapped_file(benchmark::State& state) {
    const auto tmp_file_path = create_random_temporary_file(state.range(0));

    for ([[maybe_unused]] auto _ : state) {
        silkworm::MemoryMappedFile mapped_file{tmp_file_path};
        mapped_file.advise_sequential();
        int checksum{0};
        for (auto byte : mapped_file.region()) {
            checksum += byte;
        }
        benchmark::DoNotOptimize(checksum);
    }
}

BENCHMARK(benchmark_checksum_memory_mapped_file)->Arg(k4MiBFileSize);
