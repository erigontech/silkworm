/*
   Copyright 2020 The Silkworm Authors

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

#include <boost/endian/conversion.hpp>
#include <catch2/catch.hpp>
#include <silkworm/common/temp_dir.hpp>
#include <silkworm/db/tables.hpp>
#include <boost/filesystem/operations.hpp>

namespace silkworm::etl {

namespace fs = boost::filesystem;

static std::vector<Entry> generate_entry_set(size_t size) {
    std::vector<Entry> set;
    for (size_t i = 0; i < size; i++)
    {
        Bytes key(8, '\0');
        Bytes value(8, '\0');
        boost::endian::store_big_u64(&key[0], rand() % 200000000u);
        boost::endian::store_big_u64(&value[0], rand() % 200000000u);
        set.push_back({key, value});
    }
    return set;
}

void run_collector_test(LoadFunc load_func) {
    TemporaryDirectory db_tmp_dir;
    TemporaryDirectory etl_tmp_dir;
    // Initialize random seed
    srand(time(NULL));
    // Initialize temporary Database
    lmdb::DatabaseConfig db_config{db_tmp_dir.path(), 32 * kMebi};
    db_config.set_readonly(false);
    auto env{lmdb::get_env(db_config)};
    auto txn{env->begin_rw_transaction()};
    // Generate Test Entries
    auto set{generate_entry_set(1000)};                         // 1000 entries in total
    auto collector{Collector(etl_tmp_dir.path(), 100 * 16)};    // 100 entries per file (16 bytes per entry)
    db::table::create_all(*txn);
    // Collection
    for (auto entry: set) {
        collector.collect(entry);
    }
    // Check whether temporary files were generated
    for (size_t i = 0; i < 10; i++) {
        fs::path path{etl_tmp_dir.path() / fs::path("tmp-" + std::to_string(i))};
        CHECK(fs::exists(path));
    }
    // Load data
    auto to{txn->open(db::table::kHeaderNumbers)};
    collector.load(to.get(), load_func);
    // Check wheter load was performed as intended
    for(auto &entry: set) {
        for(auto& transformed_entry: load_func(entry)) {
            auto value{to->get(transformed_entry.key)};
            CHECK(value->compare(transformed_entry.value) == 0);
        }
    }
    // Check wheter temporary files were cleaned
    for (size_t i = 0; i < 10; i++) {
        fs::path path{fs::path(etl_tmp_dir.path()) / fs::path("tmp-" + std::to_string(i))};
        CHECK(false == fs::exists(path));
    }
}

TEST_CASE("collect_and_default_load") {
    run_collector_test(identity_load);
}

TEST_CASE("collect_and_load") {
    run_collector_test([](Entry entry) {
        entry.key.at(0) = (unsigned char) 1;
        return std::vector<Entry>({entry});;
    });
}
}
