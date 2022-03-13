/*
   Copyright 2021-2022 The Silkworm Authors

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

#include <silkworm/common/directories.hpp>
#include <silkworm/db/mdbx.hpp>

static const std::map<std::string, std::string> kGeneticCode{
    {"AAA", "Lysine"},        {"AAC", "Asparagine"},    {"AAG", "Lysine"},        {"AAU", "Asparagine"},
    {"ACA", "Threonine"},     {"ACC", "Threonine"},     {"ACG", "Threonine"},     {"ACU", "Threonine"},
    {"AGA", "Arginine"},      {"AGC", "Serine"},        {"AGG", "Arginine"},      {"AGU", "Serine"},
    {"AUA", "Isoleucine"},    {"AUC", "Isoleucine"},    {"AUG", "Methionine"},    {"AUU", "Isoleucine"},
    {"CAA", "Glutamine"},     {"CAC", "Histidine"},     {"CAG", "Glutamine"},     {"CAU", "Histidine"},
    {"CCA", "Proline"},       {"CCC", "Proline"},       {"CCG", "Proline"},       {"CCU", "Proline"},
    {"CGA", "Arginine"},      {"CGC", "Arginine"},      {"CGG", "Arginine"},      {"CGU", "Arginine"},
    {"CUA", "Leucine"},       {"CUC", "Leucine"},       {"CUG", "Leucine"},       {"CUU", "Leucine"},
    {"GAA", "Glutamic acid"}, {"GAC", "Aspartic acid"}, {"GAG", "Glutamic acid"}, {"GAU", "Aspartic acid"},
    {"GCA", "Alanine"},       {"GCC", "Alanine"},       {"GCG", "Alanine"},       {"GCU", "Alanine"},
    {"GGA", "Glycine"},       {"GGC", "Glycine"},       {"GGG", "Glycine"},       {"GGU", "Glycine"},
    {"GUA", "Valine"},        {"GUC", "Valine"},        {"GUG", "Valine"},        {"GUU", "Valine"},
    {"UAA", "Stop"},          {"UAC", "Tyrosine"},      {"UAG", "Stop"},          {"UAU", "Tyrosine"},
    {"UCA", "Serine"},        {"UCC", "Serine"},        {"UCG", "Serine"},        {"UCU", "Serine"},
    {"UGA", "Stop"},          {"UGC", "Cysteine"},      {"UGG", "Tryptophan"},    {"UGU", "Cysteine"},
    {"UUA", "Leucine"},       {"UUC", "Phenylalanine"}, {"UUG", "Leucine"},       {"UUU", "Phenylalanine"},
};

namespace silkworm::db {

TEST_CASE("Cursor") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};

    const db::MapConfig map_config{"GeneticCode"};

    {
        auto txnrw{env.start_write()};
        (void)db::open_map(txnrw, map_config);
        txnrw.commit();
    }

    auto txn{env.start_read()};

    // A bit of explanation here:
    // Cursors cache may get polluted by previous tests or is empty
    // in case this is the only test being executed. So we can't rely
    // on empty() property rather we must evaluate deltas.
    size_t original_cache_size{db::Cursor::handles_cache().size()};

    {
        db::Cursor cursor1(txn, map_config);
        if (original_cache_size) {
            // One handle pulled from cache
            REQUIRE(db::Cursor::handles_cache().size() == original_cache_size - 1);
        } else {
            // A new handle has been created
            REQUIRE(db::Cursor::handles_cache().size() == original_cache_size);
        }
        REQUIRE(cursor1.get_map_stat().ms_entries == 0);
    }

    // After destruction of previous cursor cache has increased by one if it was originally empty, otherwise it is
    // restored to its original size
    if (!original_cache_size) {
        REQUIRE(db::Cursor::handles_cache().size() == original_cache_size + 1);
    } else {
        REQUIRE(db::Cursor::handles_cache().size() == original_cache_size);
    }

    txn.abort();
    txn = env.start_write();
    db::Cursor broken(txn, {"Test"});

    // Force exceed of cache size
    std::vector<db::Cursor> cursors;
    for (size_t i = 0; i < original_cache_size + 5; ++i) {
        cursors.emplace_back(txn, map_config);
    }
    REQUIRE(db::Cursor::handles_cache().empty() == true);
    cursors.clear();
    REQUIRE(db::Cursor::handles_cache().empty() == false);
    REQUIRE(db::Cursor::handles_cache().size() == original_cache_size + 5);

    db::Cursor cursor2(db::Cursor(txn, {"test"}));
    REQUIRE(cursor2.operator bool() == true);
    db::Cursor cursor3 = std::move(cursor2);
    REQUIRE(cursor2.operator bool() == false);
    REQUIRE(cursor3.operator bool() == true);

    txn.commit();

    // In another thread cursor cache must be empty
    std::atomic<size_t> other_thread_size1{0};
    std::atomic<size_t> other_thread_size2{0};
    std::thread t([&other_thread_size1, &other_thread_size2, &env]() {
        auto thread_txn{env.start_write()};
        { db::Cursor cursor(thread_txn, {"Test"}); }
        other_thread_size1 = db::Cursor::handles_cache().size();

        // Pull a handle from the pool and close the cursor directly
        // so is not returned to the pool
        db::Cursor cursor(thread_txn, {"Test"});
        cursor.close();
        other_thread_size2 = db::Cursor::handles_cache().size();
    });
    t.join();
    REQUIRE(other_thread_size1 == 1);
    REQUIRE(other_thread_size2 == 0);
}

TEST_CASE("RWTxn") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    static const char* table_name{"GeneticCode"};

    SECTION("Managed") {
        {
            auto tx{db::RWTxn(env)};
            db::Cursor table_cursor(*tx, {table_name});

            // populate table
            for (const auto& [key, value] : kGeneticCode) {
                table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
            }

            tx.commit();
        }

        auto tx{env.start_read()};
        REQUIRE(db::has_map(tx, table_name));
        const auto handle{tx.open_map(table_name)};
        REQUIRE(tx.get_map_stat(handle).ms_entries == kGeneticCode.size());
    }

    SECTION("External") {
        auto ext_tx{env.start_write()};
        {
            auto tx{db::RWTxn(ext_tx)};
            (void)tx->create_map(table_name, mdbx::key_mode::usual, mdbx::value_mode::single);
            tx.commit();  // Does not have any effect
        }
        ext_tx.abort();
        ext_tx = env.start_write();
        REQUIRE(db::has_map(ext_tx, table_name) == false);
    }
}

TEST_CASE("Cursor walk") {
    const TemporaryDirectory tmp_dir;
    db::EnvConfig db_config{tmp_dir.path().string(), /*create*/ true};
    db_config.inmemory = true;
    auto env{db::open_env(db_config)};
    auto txn{env.start_write()};

    static const char* table_name{"GeneticCode"};

    db::Cursor table_cursor(txn, {table_name});

    // A map to collect data
    std::map<std::string, std::string> data_map;
    WalkFunc save_all_data_map{[&data_map](::mdbx::cursor&, ::mdbx::cursor::move_result& entry) {
        data_map.emplace(entry.key, entry.value);
        return true;
    }};

    // A vector to collect data
    std::vector<std::pair<std::string, std::string>> data_vec;
    WalkFunc save_all_data_vec{[&data_vec](::mdbx::cursor&, ::mdbx::cursor::move_result& entry) {
        data_vec.emplace_back(entry.key, entry.value);
        return true;
    }};

    SECTION("cursor_for_each") {
        // empty table
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.empty());

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

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

        // early stop
        WalkFunc save_some_data{[&data_map](::mdbx::cursor&, ::mdbx::cursor::move_result& entry) {
            if (entry.value == "Threonine") {
                return false;
            }
            data_map.emplace(entry.key, entry.value);
            return true;
        }};
        table_cursor.to_first();
        cursor_for_each(table_cursor, save_some_data);
        REQUIRE(data_map.size() == 4);
        CHECK(data_map.at("AAA") == "Lysine");
        CHECK(data_map.at("AAC") == "Asparagine");
        CHECK(data_map.at("AAG") == "Lysine");
        CHECK(data_map.at("AAU") == "Asparagine");
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

        // early stop 1
        const auto save_some_data{[&data_map](::mdbx::cursor&, mdbx::cursor::move_result& entry) {
            if (entry.value == "Threonine") {
                return false;
            }
            data_map.emplace(entry.key, entry.value);
            return true;
        }};
        table_cursor.to_first();
        cursor_for_count(table_cursor, save_some_data, /*max_count=*/3);
        REQUIRE(data_map.size() == 3);
        CHECK(data_map.at("AAA") == "Lysine");
        CHECK(data_map.at("AAC") == "Asparagine");
        CHECK(data_map.at("AAG") == "Lysine");
        data_map.clear();

        // early stop 2
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
        cursor_erase(table_cursor);
        REQUIRE(txn.get_map_stat(table_cursor.map()).ms_entries == 0);

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // Erase all records in reverse order
        table_cursor.bind(txn, {table_name});
        cursor_erase(table_cursor, CursorMoveDirection::Reverse);
        REQUIRE(txn.get_map_stat(table_cursor.map()).ms_entries == 0);

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // Erase first 5 records
        table_cursor.to_first();
        auto erased{cursor_erase(table_cursor, 5)};
        REQUIRE(erased == 5);
        REQUIRE(txn.get_map_stat(table_cursor.map()).ms_entries == kGeneticCode.size() - erased);
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.find("AAA") == data_map.end());
        REQUIRE(data_map.find("AAC") == data_map.end());
        REQUIRE(data_map.find("AAG") == data_map.end());
        REQUIRE(data_map.find("AAU") == data_map.end());
        REQUIRE(data_map.find("ACA") == data_map.end());
        data_map.clear();

        // Erase backwards from "CAA"
        Bytes set_key(3, '\0');
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

}  // namespace silkworm::db
