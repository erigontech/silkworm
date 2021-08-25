/*
   Copyright 2020-2021 The Silkworm Authors

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

#include <csignal>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <regex>
#include <string>
#include <set>
#include <random>

#include <CLI/CLI.hpp>
#include <boost/bind.hpp>
#include <boost/format.hpp>
#include <magic_enum.hpp>

#include <silkworm/chain/config.hpp>
#include <silkworm/chain/genesis.hpp>
#include <silkworm/common/directories.hpp>
#include <silkworm/common/endian.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stages.hpp>
#include <silkworm/state/in_memory_state.hpp>
#include <silkworm/trie/hash_builder.hpp>
#include <silkworm/common/stopwatch.hpp>
#include <silkworm/etl/buffer.hpp>
#include <silkworm/etl/collector.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/common/log.hpp>


namespace fs = std::filesystem;
using namespace silkworm;
using namespace etl;

std::random_device rd;
std::default_random_engine engine{rd()};
constexpr size_t kDataSetSize = 1_Gibi;

Bytes random_bytes() {
    std::uniform_int_distribution<size_t> ud1{0, 254};  // For Bytes selector
    std::uniform_int_distribution<size_t> ud2{8, 512};  // For ByteLen selector
    Bytes ret(ud2(engine), '\0');
    for (size_t i = 0; i < ret.length(); ++i) {
        ret[i] = static_cast<uint8_t>(ud1(engine));
    }
    return ret;
}

void etl_buffer_unordered() {
    StopWatch sw;
    etl::Buffer base_buffer(kDataSetSize);
    etl::Buffer base_buffer2(kDataSetSize);

    // Feed base buffer with a random set
    std::cout << "\n Feeding buffer base ..." << std::endl;
    sw.start();
    while (!base_buffer.overflows()) {
        etl::Entry item{random_bytes(), random_bytes()};
        etl::Entry item2(item);
        base_buffer.put(std::move(item));
        base_buffer2.put(std::move(item2));
    }

    auto feed_time = sw.lap();
    sw.reset();
    std::cout << " Done in " << sw.format(feed_time.second) << std::endl;

    // Push all items in buffer default (copy)
    {
        etl::Buffer buffer(kDataSetSize);
        std::cout << "\n [Buffer-Default] First loop ..." << std::endl;
        sw.start();
        for (const auto& item : base_buffer.entries()) {
            buffer.put(item);
        }
        //buffer.sort();
        auto loop1_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default copy build] Done in " << sw.format(loop1_timings.second);

        buffer.clear();
        std::cout << "\n [Buffer-Default] Second loop ..." << std::endl;
        sw.start();
        for (const auto& item : base_buffer2.entries()) {
            buffer.put(item);
        }
        //buffer.sort();
        auto loop2_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default copy build] Done in " << sw.format(loop2_timings.second) << "\n" << std::endl;
    }

    // Push all items in buffer default (nove)
    {
        etl::Buffer buffer(kDataSetSize);
        std::cout << "\n [Buffer-Default] First loop ..." << std::endl;
        sw.start();
        for (auto&& item : (std::vector<etl::Entry> &)base_buffer.entries()) {
            buffer.put(std::move(item));
        }
        //buffer.sort();
        auto loop1_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default move build] Done in " << sw.format(loop1_timings.second);

        buffer.clear();
        std::cout << "\n [Buffer-Default] Second loop ..." << std::endl;
        sw.start();
        for (auto&& item : (std::vector<etl::Entry> &)base_buffer2.entries()) {
            buffer.put(std::move(item));
        }
        //buffer.sort();
        auto loop2_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default move build] Done in " << sw.format(loop2_timings.second) << "\n" << std::endl;
    }
}

void etl_buffer_ordered() {
    StopWatch sw;
    etl::Buffer base_buffer(kDataSetSize);
    etl::Buffer base_buffer2(kDataSetSize);
    uint64_t entry_count{0};

    // Feed base buffer with a random set
    std::cout << "\n Feeding buffer base ..." << std::endl;
    sw.start();
    while (!base_buffer.overflows()) {
        auto key{random_bytes()};
        endian::store_big_u64(&key[0], entry_count++);
        etl::Entry item{key, random_bytes()};
        etl::Entry item2(item);
        base_buffer.put(std::move(item));
        base_buffer2.put(std::move(item2));
    }

    auto feed_time = sw.lap();
    sw.reset();
    std::cout << " Done in " << sw.format(feed_time.second) << std::endl;

    // Push all items in buffer default (copy)
    {
        etl::Buffer buffer(kDataSetSize);
        std::cout << "\n [Buffer-Default] First loop ..." << std::endl;
        sw.start();
        for (const auto& item : base_buffer.entries()) {
            buffer.put(item);
        }
        //buffer.sort();
        auto loop1_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default copy build] Done in " << sw.format(loop1_timings.second);

        buffer.clear();
        std::cout << "\n [Buffer-Default] Second loop ..." << std::endl;
        sw.start();
        for (const auto& item : base_buffer2.entries()) {
            buffer.put(item);
        }
        //buffer.sort();
        auto loop2_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default copy build] Done in " << sw.format(loop2_timings.second) << "\n" << std::endl;
    }

    // Push all items in buffer default (nove)
    {
        etl::Buffer buffer(kDataSetSize);
        std::cout << "\n [Buffer-Default] First loop ..." << std::endl;
        sw.start();
        for (auto&& item : (std::vector<etl::Entry> &)base_buffer.entries()) {
            buffer.put(std::move(item));
        }
        //buffer.sort();
        auto loop1_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default move build] Done in " << sw.format(loop1_timings.second);

        buffer.clear();
        std::cout << "\n [Buffer-Default] Second loop ..." << std::endl;
        sw.start();
        for (auto&& item : (std::vector<etl::Entry> &)base_buffer2.entries()) {
            buffer.put(std::move(item));
        }
        //buffer.sort();
        auto loop2_timings{sw.lap()};
        sw.reset();
        std::cout << " [Buffer-Default move build] Done in " << sw.format(loop2_timings.second) << "\n" << std::endl;
    }
}

static std::vector<Entry> generate_entry_set(size_t size) 
{
    std::vector<Entry> entries;
    std::set<Bytes>    keys;

    while (entries.size() < size) {
        etl::Entry entry{random_bytes(), random_bytes()};

        if (keys.count(entry.key)) {
            // we want unique keys
            continue;
        }
            
        keys.insert(entry.key);
        entries.push_back(std::move(entry));
    }
    return entries;
}

static void etl_benchmark(const std::string& label, LoadFunc load_func, const std::vector<Entry> &entries) 
{
    auto do_bench = [&]() {
        StopWatch sw;
        sw.start();

        TemporaryDirectory db_tmp_dir;
        TemporaryDirectory etl_tmp_dir;
        // Initialize random seed
        srand(time(NULL));

        // Initialize temporary Database
        db::EnvConfig db_config{db_tmp_dir.path(), /*create*/ true};
        db_config.inmemory = true;

        auto env{db::open_env(db_config)};
        auto txn{env.start_write()};

        auto collector{Collector(etl_tmp_dir.path(), 100 * 16)};  // 100 entries per file (16 bytes per entry)
        db::table::create_all(txn);

        // Collection
        for (auto&& entry : entries) {
            collector.collect(entry);
        }
        // Check whether temporary files were generated
        //assert(std::distance(fs::directory_iterator{etl_tmp_dir.path()}, fs::directory_iterator{}) == 10);

        // Load data
        auto to{db::open_cursor(txn, db::table::kHeaderNumbers)};
        collector.load(to, load_func);

        auto feed_time = sw.lap();
        sw.reset();
        return sw.format(feed_time.second);
    };
    auto res1 = do_bench();
    std::cout << label << " done in " << res1 << std::endl;
}

static void bench_collector_load(const std::string &load_desc, 
                                 LoadFunc load_func, 
                                 std::vector<Entry> entries) // copy by design
{
    // bench collector with entries in random order
    // -------------------------------------------
    etl_benchmark(load_desc + "random", load_func, entries);

    // bench collector with entries sorted in increasing order
    // ------------------------------------------------------
    std::sort(entries.begin(), entries.end());
    etl_benchmark(load_desc + "sorted increasing", load_func, entries);

    // bench collector with entries sorted in decreasing order
    // ------------------------------------------------------
    std::sort(entries.begin(), entries.end(), [](const Entry &a, const Entry &b) -> bool { return b < a; });
    etl_benchmark(load_desc + "sorted decreasing", load_func, entries);
}

void etl_load() {
    SILKWORM_LOG_VERBOSITY(LogLevel::None);

    //size_t kDataSetSize{1_Gibi};
    size_t kDataSetSize{4096};
    std::vector<Entry> entries { generate_entry_set(kDataSetSize) };
    
    // first test with default load
    // ----------------------------
    bench_collector_load("default load: ", nullptr, entries);

    // first test with custom load
    // ---------------------------
    auto load_fn = [](Entry entry, mdbx::cursor& table, MDBX_put_flags_t flags) {
        (void)flags;
        entry.key.at(0) = 1;
        table.upsert(db::to_slice(entry.key), db::to_slice(entry.value));
    };

    bench_collector_load("custom load: ", load_fn, entries);
}

int main(int argc, char* argv[]) {

    CLI::App app_main("Silkworm db tool");
    app_main.require_subcommand(1);  // At least 1 subcommand is required
    // List tables and gives info about storage
    auto benchmark_etl_buffer_unordered = app_main.add_subcommand("buffer_unordered", "Benchmark etl::Buffer");
    auto benchmark_etl_buffer_ordered = app_main.add_subcommand("buffer_ordered", "Benchmark etl::Buffer");
    auto benchmark_etl_load = app_main.add_subcommand("etl_load", "Benchmark collector::load");
    /*
     * Parse arguments and validate
     */
    CLI11_PARSE(app_main, argc, argv);

    // Execute subcommand actions
    if (*benchmark_etl_buffer_unordered) {
        etl_buffer_unordered();
    } else if (*benchmark_etl_buffer_ordered) {
        etl_buffer_ordered();
    } else if(*benchmark_etl_load) {
        etl_load();
    }
    return 0;
}
