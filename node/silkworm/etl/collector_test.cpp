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

#include "collector.hpp"

#include <filesystem>
#include <set>

#include <boost/endian/conversion.hpp>
#include <catch2/catch.hpp>

#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/tables.hpp>

namespace silkworm::etl {

namespace fs = std::filesystem;

static std::vector<Entry> generate_entry_set(size_t size) {
    std::vector<Entry> pairs;
    std::set<Bytes> keys;
    while (pairs.size() < size) {
        Bytes key(8, '\0');
        Bytes value(8, '\0');
        boost::endian::store_big_u64(&key[0], rand() % 200000000u);
        boost::endian::store_big_u64(&value[0], rand() % 200000000u);

        if (keys.count(key)) {
            // we want unique keys
            continue;
        } else {
            keys.insert(key);
        }

        pairs.push_back({key, value});
    }
    return pairs;
}

void run_collector_test(LoadFunc load_func) {
    TemporaryDirectory db_tmp_dir;
    TemporaryDirectory etl_tmp_dir;
    // Initialize random seed
    srand(time(NULL));

    // Initialize temporary Database
    db::EnvConfig db_config{db_tmp_dir.path(), /*create*/ true};
    db_config.inmemory = true;

    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    // Generate Test Entries
    auto set{generate_entry_set(1000)};                       // 1000 entries in total
    auto collector{Collector(etl_tmp_dir.path(), 100 * 16)};  // 100 entries per file (16 bytes per entry)
    db::table::create_all(txn);
    // Collection
    for (auto entry : set) {
        collector.collect(entry);
    }
    // Check whether temporary files were generated
    CHECK(std::distance(fs::directory_iterator{etl_tmp_dir.path()}, fs::directory_iterator{}) == 10);

    // Load data
    auto to{db::open_cursor(txn, db::table::kHeaderNumbers)};
    collector.load(to, load_func);
    // Check wheter temporary files were cleaned
    CHECK(std::distance(fs::directory_iterator{etl_tmp_dir.path()}, fs::directory_iterator{}) == 0);
}

TEST_CASE("collect_and_default_load") { run_collector_test(nullptr); }

TEST_CASE("collect_and_load") {
    run_collector_test([](Entry entry, mdbx::cursor& table, MDBX_put_flags_t flags) {
        (void)flags;
        entry.key.at(0) = 1;
        table.upsert(db::to_slice(entry.key), db::to_slice(entry.value));
    });
}

}  // namespace silkworm::etl
