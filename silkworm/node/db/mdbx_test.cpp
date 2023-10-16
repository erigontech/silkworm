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

#include <atomic>
#include <map>
#include <thread>

#include <catch2/catch.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/node/test/context.hpp>

static const std::map<std::string, std::string> kGeneticCode{
    {"AAA", "Lysine"},
    {"AAC", "Asparagine"},
    {"AAG", "Lysine"},
    {"AAU", "Asparagine"},
    {"ACA", "Threonine"},
    {"ACC", "Threonine"},
    {"ACG", "Threonine"},
    {"ACU", "Threonine"},
    {"AGA", "Arginine"},
    {"AGC", "Serine"},
    {"AGG", "Arginine"},
    {"AGU", "Serine"},
    {"AUA", "Isoleucine"},
    {"AUC", "Isoleucine"},
    {"AUG", "Methionine"},
    {"AUU", "Isoleucine"},
    {"CAA", "Glutamine"},
    {"CAC", "Histidine"},
    {"CAG", "Glutamine"},
    {"CAU", "Histidine"},
    {"CCA", "Proline"},
    {"CCC", "Proline"},
    {"CCG", "Proline"},
    {"CCU", "Proline"},
    {"CGA", "Arginine"},
    {"CGC", "Arginine"},
    {"CGG", "Arginine"},
    {"CGU", "Arginine"},
    {"CUA", "Leucine"},
    {"CUC", "Leucine"},
    {"CUG", "Leucine"},
    {"CUU", "Leucine"},
    {"GAA", "Glutamic acid"},
    {"GAC", "Aspartic acid"},
    {"GAG", "Glutamic acid"},
    {"GAU", "Aspartic acid"},
    {"GCA", "Alanine"},
    {"GCC", "Alanine"},
    {"GCG", "Alanine"},
    {"GCU", "Alanine"},
    {"GGA", "Glycine"},
    {"GGC", "Glycine"},
    {"GGG", "Glycine"},
    {"GGU", "Glycine"},
    {"GUA", "Valine"},
    {"GUC", "Valine"},
    {"GUG", "Valine"},
    {"GUU", "Valine"},
    {"UAA", "Stop"},
    {"UAC", "Tyrosine"},
    {"UAG", "Stop"},
    {"UAU", "Tyrosine"},
    {"UCA", "Serine"},
    {"UCC", "Serine"},
    {"UCG", "Serine"},
    {"UCU", "Serine"},
    {"UGA", "Stop"},
    {"UGC", "Cysteine"},
    {"UGG", "Tryptophan"},
    {"UGU", "Cysteine"},
    {"UUA", "Leucine"},
    {"UUC", "Phenylalanine"},
    {"UUG", "Leucine"},
    {"UUU", "Phenylalanine"},
};

namespace silkworm::db {

TEST_CASE("Environment opening") {
    SECTION("Default page size on creation") {
        const TemporaryDirectory tmp_dir;
        db::EnvConfig db_config{
            .path = tmp_dir.path().string(),
            .create = true,
            .in_memory = true,
        };
        REQUIRE(db_config.page_size == os::page_size());
        const auto env{db::open_env(db_config)};
        CHECK(env.get_pagesize() == db_config.page_size);
    }

    SECTION("Non default page size on creation") {
        const TemporaryDirectory tmp_dir;
        db::EnvConfig db_config{
            .path = tmp_dir.path().string(),
            .create = true,
            .in_memory = true,
            .page_size = os::page_size() / 2,
        };
        const auto env{db::open_env(db_config)};
        CHECK(env.get_pagesize() == db_config.page_size);
    }

    SECTION("Read page size on opening") {
        const TemporaryDirectory tmp_dir;
        {
            db::EnvConfig db_config{
                .path = tmp_dir.path().string(),
                .create = true,
                .in_memory = true,
                .page_size = os::page_size() / 2,
            };
            (void)db::open_env(db_config);
        }

        {
            // Try to reopen same db with another page size
            db::EnvConfig db_config{
                .path = tmp_dir.path().string(),
                .create = false,
                .in_memory = true,
                .page_size = os::page_size() * 2,
            };
            const auto env{db::open_env(db_config)};
            CHECK(env.get_pagesize() == os::page_size() / 2);
        }
    }
}

TEST_CASE("Cursor") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
    db_config.in_memory = true;
    auto env{db::open_env(db_config)};

    const db::MapConfig map_config{"GeneticCode"};

    {
        auto rw_txn{env.start_write()};
        CHECK(db::list_maps(rw_txn).empty());
        (void)db::open_map(rw_txn, map_config);
        rw_txn.commit();
    }

    auto txn{env.start_read()};

    const auto& map_names = db::list_maps(txn);
    CHECK(map_names.size() == 1);
    CHECK(map_names[0] == "GeneticCode");

    // A bit of explanation here:
    // Cursors cache may get polluted by previous tests or is empty
    // in case this is the only test being executed. So we can't rely
    // on empty() property rather we must evaluate deltas.
    size_t original_cache_size{db::PooledCursor::handles_cache().size()};

    {
        db::PooledCursor cursor1(txn, map_config);
        if (original_cache_size) {
            // One handle pulled from cache
            REQUIRE(db::PooledCursor::handles_cache().size() == original_cache_size - 1);
        } else {
            // A new handle has been created
            REQUIRE(db::PooledCursor::handles_cache().size() == original_cache_size);
        }
        REQUIRE(cursor1.get_map_stat().ms_entries == 0);
    }

    // After destruction of previous cursor cache has increased by one if it was originally empty, otherwise it is
    // restored to its original size
    if (!original_cache_size) {
        REQUIRE(db::PooledCursor::handles_cache().size() == original_cache_size + 1);
    } else {
        REQUIRE(db::PooledCursor::handles_cache().size() == original_cache_size);
    }

    txn.abort();
    txn = env.start_write();
    db::PooledCursor broken(txn, {"Test"});

    // Force exceed of cache size
    std::vector<db::PooledCursor> cursors;
    for (size_t i = 0; i < original_cache_size + 5; ++i) {
        cursors.emplace_back(txn, map_config);
    }
    REQUIRE(db::PooledCursor::handles_cache().empty() == true);
    cursors.clear();
    REQUIRE(db::PooledCursor::handles_cache().empty() == false);
    REQUIRE(db::PooledCursor::handles_cache().size() == original_cache_size + 5);

    db::PooledCursor cursor2(db::PooledCursor(txn, {"test"}));
    REQUIRE(cursor2.operator bool() == true);
    db::PooledCursor cursor3 = std::move(cursor2);
    // REQUIRE(cursor2.operator bool() == false);
    REQUIRE(cursor3.operator bool() == true);

    txn.commit();

    // In another thread cursor cache must be empty
    std::atomic<size_t> other_thread_size1{0};
    std::atomic<size_t> other_thread_size2{0};
    std::thread t([&other_thread_size1, &other_thread_size2, &env]() {
        auto thread_txn{env.start_write()};
        { db::PooledCursor cursor(thread_txn, {"Test"}); }
        other_thread_size1 = db::PooledCursor::handles_cache().size();

        // Pull a handle from the pool and close the cursor directly
        // so is not returned to the pool
        db::PooledCursor cursor(thread_txn, {"Test"});
        cursor.close();
        other_thread_size2 = db::PooledCursor::handles_cache().size();
    });
    t.join();
    REQUIRE(other_thread_size1 == 1);
    REQUIRE(other_thread_size2 == 0);
}

TEST_CASE("RWTxn") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
    db_config.in_memory = true;
    auto env{db::open_env(db_config)};
    static const char* table_name{"GeneticCode"};

    SECTION("Managed") {
        {
            auto tx{db::RWTxnManaged(env)};
            db::PooledCursor table_cursor(*tx, {table_name});

            // populate table
            for (const auto& [key, value] : kGeneticCode) {
                table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
            }

            tx.commit_and_renew();
        }

        auto tx{env.start_read()};
        db::PooledCursor table_cursor(tx, {table_name});
        REQUIRE(table_cursor.empty() == false);
    }

    SECTION("External") {
        RWTxnManaged tx{env};
        tx.disable_commit();
        {
            (void)tx->create_map(table_name, mdbx::key_mode::usual, mdbx::value_mode::single);
            tx.commit_and_renew();  // Does not have any effect
        }
        tx.abort();
        RWTxnManaged tx2{env};
        REQUIRE(db::has_map(tx2, table_name) == false);
    }

    SECTION("Cursor from RWTxn") {
        auto tx{db::RWTxnManaged(env)};
        db::PooledCursor table_cursor(tx, {table_name});
        REQUIRE(table_cursor.empty());
        REQUIRE_NOTHROW(table_cursor.bind(tx, {table_name}));
        table_cursor.close();
        REQUIRE_THROWS(table_cursor.bind(tx, {table_name}));
    }
}

TEST_CASE("Cursor walk") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
    db_config.in_memory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    static const char* table_name{"GeneticCode"};

    db::PooledCursor table_cursor(txn, {table_name});

    // A map to collect data
    std::map<std::string, std::string> data_map;
    auto save_all_data_map{[&data_map](ByteView key, ByteView value) {
        data_map.emplace(byte_view_to_string_view(key), byte_view_to_string_view(value));
    }};

    // A vector to collect data
    std::vector<std::pair<std::string, std::string>> data_vec;
    auto save_all_data_vec{[&data_vec](ByteView key, ByteView value) {
        data_vec.emplace_back(byte_view_to_string_view(key), byte_view_to_string_view(value));
    }};

    SECTION("cursor_for_each") {
        // empty table
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.empty());
        REQUIRE(table_cursor.empty() == true);

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }
        REQUIRE(table_cursor.size() == kGeneticCode.size());
        REQUIRE(table_cursor.empty() == false);

        // Rebind cursor so its position is undefined
        table_cursor.bind(txn, {table_name});
        REQUIRE(table_cursor.eof() == true);

        // read entire table forward
        cursor_for_each(table_cursor, save_all_data_map);
        CHECK(data_map == kGeneticCode);
        data_map.clear();

        // read entire table backwards
        table_cursor.bind(txn, {table_name});
        cursor_for_each(table_cursor, save_all_data_map, CursorMoveDirection::Reverse);
        CHECK(data_map == kGeneticCode);
        data_map.clear();

        // Ensure the order is reversed
        table_cursor.bind(txn, {table_name});
        cursor_for_each(table_cursor, save_all_data_vec, CursorMoveDirection::Reverse);
        CHECK(data_vec.back().second == kGeneticCode.at("AAA"));

        // late start
        table_cursor.find("UUG");
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.size() == 2);
        CHECK(data_map.at("UUG") == "Leucine");
        CHECK(data_map.at("UUU") == "Phenylalanine");
        data_map.clear();
    }

    SECTION("cursor_erase_prefix") {
        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }
        REQUIRE(table_cursor.size() == kGeneticCode.size());
        REQUIRE(table_cursor.empty() == false);

        // Delete all records starting with "AC"
        Bytes prefix{};
        prefix.append({'A', 'C'});
        auto erased{cursor_erase_prefix(table_cursor, prefix)};
        REQUIRE(erased == 4);
        REQUIRE(table_cursor.size() == (kGeneticCode.size() - erased));
    }

    SECTION("cursor_for_prefix") {
        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        Bytes prefix{};
        prefix.assign({'A', 'A'});
        auto count{cursor_for_prefix(table_cursor,
                                     prefix,
                                     [](ByteView, ByteView) {
                                         // do nothing
                                     })};
        REQUIRE(count == 4);
    }

    SECTION("cursor_for_count") {
        // empty table
        cursor_for_count(table_cursor, save_all_data_map, /*max_count=*/5);
        REQUIRE(data_map.empty());

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // read entire table
        table_cursor.to_first();
        cursor_for_count(table_cursor, save_all_data_map, /*max_count=*/100);
        CHECK(data_map == kGeneticCode);
        data_map.clear();

        // read some first entries
        table_cursor.to_first();
        cursor_for_count(table_cursor, save_all_data_map, /*max_count=*/5);
        REQUIRE(data_map.size() == 5);
        CHECK(data_map.at("AAA") == "Lysine");
        CHECK(data_map.at("AAC") == "Asparagine");
        CHECK(data_map.at("AAG") == "Lysine");
        CHECK(data_map.at("AAU") == "Asparagine");
        CHECK(data_map.at("ACA") == "Threonine");
        data_map.clear();

        // late start
        table_cursor.find("UUA");
        cursor_for_count(table_cursor, save_all_data_map, /*max_count=*/3);
        REQUIRE(data_map.size() == 3);
        CHECK(data_map.at("UUA") == "Leucine");
        CHECK(data_map.at("UUC") == "Phenylalanine");
        CHECK(data_map.at("UUG") == "Leucine");
        data_map.clear();

        // reverse read
        table_cursor.to_last();
        cursor_for_count(table_cursor, save_all_data_map, /*max_count=*/4, CursorMoveDirection::Reverse);
        REQUIRE(data_map.size() == 4);
        CHECK(data_map.at("UUA") == "Leucine");
        CHECK(data_map.at("UUC") == "Phenylalanine");
        CHECK(data_map.at("UUG") == "Leucine");
        CHECK(data_map.at("UUU") == "Phenylalanine");
        data_map.clear();

        // selective save 1
        const auto save_some_data{[&data_map](ByteView key, ByteView value) {
            if (value != string_view_to_byte_view("Threonine")) {
                data_map.emplace(byte_view_to_string_view(key), byte_view_to_string_view(value));
            }
        }};
        table_cursor.to_first();
        cursor_for_count(table_cursor, save_some_data, /*max_count=*/3);
        REQUIRE(data_map.size() == 3);
        CHECK(data_map.at("AAA") == "Lysine");
        CHECK(data_map.at("AAC") == "Asparagine");
        CHECK(data_map.at("AAG") == "Lysine");
        data_map.clear();

        // selective save 2
        table_cursor.to_first();
        cursor_for_count(table_cursor, save_some_data, /*max_count=*/5);
        REQUIRE(data_map.size() == 4);
        CHECK(data_map.at("AAA") == "Lysine");
        CHECK(data_map.at("AAC") == "Asparagine");
        CHECK(data_map.at("AAG") == "Lysine");
        CHECK(data_map.at("AAU") == "Asparagine");
    }

    SECTION("cursor_erase") {
        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // Erase all records in forward order
        table_cursor.bind(txn, {table_name});
        cursor_erase(table_cursor, {});
        REQUIRE(txn.get_map_stat(table_cursor.map()).ms_entries == 0);

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // Erase all records in reverse order
        Bytes set_key(3, '\0');
        set_key[0] = 'X';
        set_key[1] = 'X';
        set_key[2] = 'X';
        table_cursor.bind(txn, {table_name});
        cursor_erase(table_cursor, set_key, CursorMoveDirection::Reverse);
        REQUIRE(txn.get_map_stat(table_cursor.map()).ms_entries == 0);

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // Erase backwards from "CAA"
        set_key[0] = 'C';
        set_key[1] = 'A';
        set_key[2] = 'A';
        cursor_erase(table_cursor, set_key, CursorMoveDirection::Reverse);
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.begin()->second == "Glutamine");

        // Erase forward from "UAA"
        set_key[0] = 'U';
        set_key[1] = 'A';
        set_key[2] = 'A';
        cursor_erase(table_cursor, set_key, CursorMoveDirection::Forward);
        data_map.clear();
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.rbegin()->second == "Valine");
    }
}

TEST_CASE("OF pages") {
    test::Context context;
    db::RWTxn& txn = context.rw_txn();

    SECTION("No overflow") {
        db::PooledCursor target(txn, db::table::kAccountHistory);
        Bytes key(20, '\0');
        Bytes value(db::max_value_size_for_leaf_page(*txn, key.size()), '\0');
        target.insert(db::to_slice(key), db::to_slice(value));
        txn.commit_and_renew();
        target.bind(txn, db::table::kAccountHistory);
        auto stats{target.get_map_stat()};
        REQUIRE(!stats.ms_overflow_pages);
    }

    SECTION("Let's overflow") {
        db::PooledCursor target(txn, db::table::kAccountHistory);
        Bytes key(20, '\0');
        Bytes value(db::max_value_size_for_leaf_page(*txn, key.size()) + /*any extra value */ 1, '\0');
        target.insert(db::to_slice(key), db::to_slice(value));
        txn.commit_and_renew();
        target.bind(txn, db::table::kAccountHistory);
        auto stats{target.get_map_stat()};
        REQUIRE(stats.ms_overflow_pages);
    }
}

}  // namespace silkworm::db
