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

#include "collector.hpp"

#include <filesystem>
#include <set>
#include <thread>

#include <catch2/catch.hpp>

#include <silkworm/core/common/endian.hpp>
#include <silkworm/core/common/random_number.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/node/test/context.hpp>

namespace silkworm::etl {

namespace fs = std::filesystem;

static std::vector<Entry> generate_entry_set(size_t size) {
    std::vector<Entry> pairs;
    std::set<Bytes> keys;
    RandomNumber rnd{0, 200000000};
    while (pairs.size() < size) {
        Bytes key(8, '\0');
        endian::store_big_u64(&key[0], rnd.generate_one());

        if (keys.contains(key)) {
            // we want unique keys
            continue;
        } else {
            keys.insert(key);
        }
        if (pairs.size() % 100) {
            Bytes value(8, '\0');
            endian::store_big_u64(&value[0], rnd.generate_one());
            pairs.emplace_back(key, value);
        } else {
            Bytes value;
            pairs.emplace_back(key, value);
        }
    }
    return pairs;
}

void run_collector_test(const LoadFunc& load_func, bool do_copy = true) {
    test::Context context;

    // Generate Test Entries
    auto set{generate_entry_set(1000)};  // 1000 entries in total
    size_t generated_size{0};
    for (const auto& entry : set) {
        generated_size += entry.size() + /* each flushed record stores also length of key and length of value */ 8;
    }
    auto collector{Collector(context.dir().etl().path(), generated_size / 10)};  // expect 10 files

    // Collection
    for (auto&& entry : set) {
        if (do_copy)
            collector.collect(entry);  // copy is slower... do only if entry is reused afterwards
        else
            collector.collect(std::move(entry));
    }
    // Check whether temporary files were generated
    CHECK(std::distance(fs::directory_iterator{context.dir().etl().path()}, fs::directory_iterator{}) == 10);
    CHECK(collector.bytes_size() == (generated_size - 8 * set.size()));

    // Load data while reading loading key from another thread
    auto key_reader_thread = std::thread([&collector]() -> void {
        size_t max_tries{10};
        while (--max_tries) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            const auto read_key = collector.get_load_key();
            log::Info("Loading ...", {"key", read_key});
        }
    });

    db::PooledCursor to{context.rw_txn(), db::table::kHeaderNumbers};
    collector.load(to, load_func);
    // Check whether temporary files were cleaned
    CHECK(std::distance(fs::directory_iterator{context.dir().etl().path()}, fs::directory_iterator{}) == 0);
    key_reader_thread.join();
}

TEST_CASE("collect_and_default_load") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test(nullptr);
}

TEST_CASE("collect_and_default_load_move") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test(nullptr, false);
}

TEST_CASE("collect_and_load") {
    test_util::SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test([](const Entry& entry, auto& table, MDBX_put_flags_t) {
        Bytes key{entry.key};
        key.at(0) = 1;
        table.upsert(db::to_slice(key), db::to_slice(entry.value));
    });
}

}  // namespace silkworm::etl
