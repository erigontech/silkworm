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

#include <set>
#include <thread>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/random_number.hpp>
#include <silkworm/db/etl/in_memory_collector.hpp>
#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/test_util/log.hpp>

#include "util.hpp"

namespace silkworm::db::etl_mdbx {

// Function pointer to process Load on before Load data into tables
using KVLoadFunc = std::function<void(const Bytes& key, const Bytes& value,
                                      db::RWCursorDupSort&, MDBX_put_flags_t)>;

template <typename CollectorStorage = etl::MapStorage>
class InMemoryCollector : public etl::InMemoryCollector<CollectorStorage> {
  public:
    using etl::InMemoryCollector<CollectorStorage>::InMemoryCollector;

    //! \brief Loads and optionally transforms collected entries into db
    //! \param [in] target : a cursor opened on target table and owned by caller (can be empty)
    //! \param [in] load_func : Pointer to function transforming collected entries. If NULL no transform is executed
    //! \param [in] flags : Optional put flags for append or upsert (default) items
    void load(
        db::RWCursorDupSort& target,
        const KVLoadFunc& load_func = {},
        MDBX_put_flags_t flags = MDBX_put_flags_t::MDBX_UPSERT) {
        etl::KVLoadFunc base_load_func = [&](const Bytes& key, const Bytes& value) {
            if (load_func) {
                load_func(key, value, target, flags);
            } else {
                mdbx::slice k{db::to_slice(key)};
                if (value.empty()) {
                    target.erase(k);
                } else {
                    mdbx::slice v{db::to_slice(value)};
                    mdbx::error::success_or_throw(target.put(k, &v, flags));
                }
            }
        };

        this->etl::InMemoryCollector<CollectorStorage>::load(base_load_func);
    }
};

using etl::Entry;
using etl::MapStorage;
using etl::VectorStorage;
using silkworm::test_util::SetLogVerbosityGuard;

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
        }
        keys.insert(key);
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

template <typename COLLECTOR>
void run_collector_test(const KVLoadFunc& load_func, bool do_copy = true) {
    db::test_util::TempChainData context;

    // Generate Test Entries
    auto set{generate_entry_set(1000)};  // 1000 entries in total
    size_t generated_size{0};
    for (const auto& entry : set) {
        generated_size += entry.size();
    }

    // Collection
    COLLECTOR collector{set.size()};

    for (auto&& entry : set) {
        if (do_copy)
            collector.collect(entry);  // copy is slower... do only if entry is reused afterwards
        else
            collector.collect(std::move(entry));
    }

    // Check size
    CHECK(collector.size() == set.size());
    CHECK(collector.bytes_size() == generated_size);

    // Reading loading key from another thread
    auto key_reader_thread = std::thread([&collector]() -> void {
        size_t max_tries{10};
        while (--max_tries) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            const auto read_key = collector.get_load_key();
            log::Info("Loading ...", {"key", read_key});
        }
    });

    // Load data
    db::PooledCursor to{context.rw_txn(), db::table::kHeaderNumbers};
    collector.load(to, load_func);

    if (load_func) {
        size_t found_items{0};
        db::PooledCursor from{context.rw_txn(), db::table::kHeaderNumbers};
        auto data = from.to_first();
        while (data) {
            auto key = db::from_slice(data.key);
            auto value = db::from_slice(data.value);
            found_items++;

            // find key in set and compare value
            auto it = std::find_if(set.begin(), set.end(), [&key](const Entry& entry) {
                return entry.key == key;
            });
            CHECK(it != set.end());
            CHECK(it->value == value);

            data = from.to_next(/*throw_notfound =*/false);
        }
        CHECK(found_items == set.size());
    }

    key_reader_thread.join();
}

TEST_CASE("collect_and_default_load_in_memory_map") {
    SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test<InMemoryCollector<MapStorage>>(nullptr);
}

TEST_CASE("collect_and_default_load_in_memory_vector") {
    SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test<InMemoryCollector<VectorStorage>>(nullptr);
}

TEST_CASE("collect_and_default_load_move_in_memory_map") {
    SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test<InMemoryCollector<MapStorage>>(nullptr, false);
}

TEST_CASE("collect_and_default_load_move_in_memory_vector") {
    SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test<InMemoryCollector<VectorStorage>>(nullptr, false);
}

TEST_CASE("collect_and_load_in_memory_map") {
    SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test<InMemoryCollector<MapStorage>>([](const Bytes& ekey, const Bytes& evalue, auto& table, MDBX_put_flags_t) {
        table.upsert(db::to_slice(ekey), db::to_slice(evalue));
    });
}

TEST_CASE("collect_and_load_in_memory_vector") {
    SetLogVerbosityGuard log_guard{log::Level::kNone};
    run_collector_test<InMemoryCollector<VectorStorage>>([](const Bytes& ekey, const Bytes& evalue, auto& table, MDBX_put_flags_t) {
        table.upsert(db::to_slice(ekey), db::to_slice(evalue));
    });
}

}  // namespace silkworm::db::etl_mdbx