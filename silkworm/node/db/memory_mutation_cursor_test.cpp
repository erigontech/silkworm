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

#include "memory_mutation_cursor.hpp"

#include <catch2/catch.hpp>

#include <silkworm/node/common/test_context.hpp>

namespace silkworm::db {

const MapConfig kTestMap{"TestTable"};
const MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

static mdbx::env_managed create_main_env(const db::EnvConfig& main_db_config) {
    auto main_env = db::open_env(main_db_config);
    RWTxn main_txn{main_env};
    table::check_or_create_chaindata_tables(main_txn);
    open_map(main_txn, kTestMap);
    open_map(main_txn, kTestMultiMap);
    main_txn.commit_and_stop();
    return main_env;
}

static void fill_tables(RWTxn& rw_txn) {
    db::PooledCursor rw_cursor1{rw_txn, kTestMap};
    rw_cursor1.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
    rw_cursor1.upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
    db::PooledCursor rw_cursor2{rw_txn, kTestMultiMap};
    rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
    rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"11"});
    rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"22"});
    rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"22"});
    rw_txn.commit_and_renew();
}

static void alter_tables(RWTxn& rw_txn) {
    db::PooledCursor rw_cursor1{rw_txn, kTestMap};
    rw_cursor1.upsert(mdbx::slice{"CC"}, mdbx::slice{"22"});
    db::PooledCursor rw_cursor2{rw_txn, kTestMultiMap};
    rw_cursor2.upsert(mdbx::slice{"AA"}, mdbx::slice{"33"});
    rw_cursor2.upsert(mdbx::slice{"BB"}, mdbx::slice{"33"});
    rw_txn.commit_and_renew();
}

struct MemoryMutationCursorTest {
    explicit MemoryMutationCursorTest() {
        open_map(mutation, kTestMap);
        open_map(mutation, kTestMultiMap);
        mutation.commit_and_renew();
    }

    void fill_main_tables() {
        fill_tables(main_txn);
    }

    void fill_mutation_tables() {
        fill_tables(mutation);
    }

    void alter_main_tables() {
        alter_tables(main_txn);
    }

    void alter_mutation_tables() {
        alter_tables(mutation);
    }

    const TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path() / "main_db", true};
    db::EnvConfig main_db_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .in_memory = true,
    };
    mdbx::env_managed main_env{create_main_env(main_db_config)};
    RWTxn main_txn{main_env};
    MemoryOverlay overlay{tmp_dir.path()};
    MemoryMutation mutation{overlay, &main_txn};
};

// Skip in TSAN build due to false positive lock-order-inversion: https://github.com/google/sanitizers/issues/814
#ifndef SILKWORM_SANITIZE

const MapConfig kNonexistentTestMap{"NonexistentTable"};
const MapConfig kNonexistentTestMultiMap{"NonexistentMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

TEST_CASE("MemoryMutationCursor: initialization", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    SECTION("Empty overlay: Create memory mutation cursor") {
        // Nonexistent tables
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kNonexistentTestMap});
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kNonexistentTestMultiMap});

        // Existent tables
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kTestMap});
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kTestMultiMap});

        // Check initial state
        MemoryMutationCursor mutation_cursor1{test1.mutation, kTestMap};
        CHECK_NOTHROW(!mutation_cursor1.is_table_cleared());
        CHECK_NOTHROW(!mutation_cursor1.is_entry_deleted(Slice{}));
        MemoryMutationCursor mutation_cursor2{test1.mutation, kTestMultiMap};
        CHECK_NOTHROW(!mutation_cursor2.is_table_cleared());
        CHECK_NOTHROW(!mutation_cursor2.is_entry_deleted(Slice{}));

        // Create many cursors
        std::vector<std::unique_ptr<MemoryMutationCursor>> memory_cursors;
        for (int i{0}; i < 10; ++i) {
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test1.mutation, kTestMap)));
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test1.mutation, kTestMultiMap)));
        }

        // Check predefined tables
        for (const auto& table : table::kChainDataTables) {
            MemoryMutationCursor mutation_cursor{test1.mutation, table};
            CHECK_NOTHROW(has_map(test1.mutation, table.name));
            CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
            CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}));
        }
    }

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    SECTION("Nonempty overlay: Check tables") {
        for (const auto& table : {kTestMap, kTestMultiMap}) {
            MemoryMutationCursor mutation_cursor{test2.mutation, table};
            CHECK_NOTHROW(mutation_cursor.to_first());
            CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
            CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}));
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_first", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (auto [tag, test] : mutation_tests) {
        SECTION(tag + ": to_first on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.to_first(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.to_first(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor1.to_first(/*throw_notfound=*/false));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.to_first(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.to_first(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.to_first(/*throw_notfound=*/false));
        }

        SECTION(tag + ": to_first on existent table") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            const auto result1 = mutation_cursor1.to_first();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");
            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMap};
            const auto result2 = mutation_cursor2.to_first(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");
            MemoryMutationCursor mutation_cursor3{test->mutation, kTestMap};
            const auto result3 = mutation_cursor3.to_first(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");

            MemoryMutationCursor mutation_cursor4{test->mutation, kTestMultiMap};
            const auto result4 = mutation_cursor4.to_first();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");

            MemoryMutationCursor mutation_cursor5{test->mutation, kTestMultiMap};
            const auto result5 = mutation_cursor5.to_first(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");

            MemoryMutationCursor mutation_cursor6{test->mutation, kTestMultiMap};
            const auto result6 = mutation_cursor6.to_first(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
        }

        SECTION(tag + ": to_first operation is idempotent") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            const auto result1 = mutation_cursor1.to_first();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");
            const auto result2 = mutation_cursor1.to_first();
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMultiMap};
            const auto result3 = mutation_cursor2.to_first();
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");
            const auto result4 = mutation_cursor2.to_first();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_next", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (auto [tag, test] : mutation_tests) {
        SECTION(tag + ": to_next on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.to_next(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.to_next(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor1.to_next(/*throw_notfound=*/false));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.to_next(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.to_next(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.to_next(/*throw_notfound=*/false));
        }

        SECTION(tag + ": to_next on existent table w/ positioning: OK") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.to_next();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMap};
            REQUIRE(mutation_cursor2.to_first());
            const auto result2 = mutation_cursor2.to_next(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor3{test->mutation, kTestMap};
            REQUIRE(mutation_cursor3.to_first());
            const auto result3 = mutation_cursor3.to_next(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");

            MemoryMutationCursor mutation_cursor4{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor4.to_first());
            const auto result4 = mutation_cursor4.to_next();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");

            MemoryMutationCursor mutation_cursor5{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor5.to_first());
            const auto result5 = mutation_cursor5.to_next(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "11");

            MemoryMutationCursor mutation_cursor6{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor6.to_first());
            const auto result6 = mutation_cursor6.to_next(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "11");
        }

        SECTION(tag + ": to_next multiple operations") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            REQUIRE(mutation_cursor1.to_first(/*throw_notfound=*/false));
            const auto result1 = mutation_cursor1.to_next(/*throw_notfound=*/false);
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");
            const auto result2 = mutation_cursor1.to_next(/*throw_notfound=*/false);
            CHECK(!result2.done);
            REQUIRE(mutation_cursor1.to_last(/*throw_notfound=*/false));
            const auto result3 = mutation_cursor1.to_next(/*throw_notfound=*/false);
            CHECK(!result3.done);

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor2.to_first(/*throw_notfound=*/false));
            const auto result4 = mutation_cursor2.to_next(/*throw_notfound=*/false);
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");
            const auto result5 = mutation_cursor2.to_next(/*throw_notfound=*/false);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "22");
            REQUIRE(mutation_cursor2.to_last(/*throw_notfound=*/false));
            const auto result6 = mutation_cursor2.to_next(/*throw_notfound=*/false);
            CHECK(!result6.done);
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_current_next_multi", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (auto [tag, test] : mutation_tests) {
        SECTION(tag + ": to_current_next_multi on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.to_current_next_multi(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.to_current_next_multi(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor1.to_current_next_multi(/*throw_notfound=*/false));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.to_current_next_multi(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.to_current_next_multi(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.to_current_next_multi(/*throw_notfound=*/false));
        }

        SECTION(tag + ": to_current_next_multi on existent table w/ positioning: OK") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.to_current_next_multi();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMap};
            REQUIRE(mutation_cursor2.to_first());
            const auto result2 = mutation_cursor2.to_current_next_multi(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor3{test->mutation, kTestMap};
            REQUIRE(mutation_cursor3.to_first());
            const auto result3 = mutation_cursor3.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");

            MemoryMutationCursor mutation_cursor4{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor4.to_first());
            const auto result4 = mutation_cursor4.to_current_next_multi();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");

            MemoryMutationCursor mutation_cursor5{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor5.to_first());
            const auto result5 = mutation_cursor5.to_current_next_multi(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "11");

            MemoryMutationCursor mutation_cursor6{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor6.to_first());
            const auto result6 = mutation_cursor6.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "11");
        }

        SECTION(tag + ": to_current_next_multi multiple operations") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            REQUIRE(mutation_cursor1.to_first(/*throw_notfound=*/false));
            const auto result1 = mutation_cursor1.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");
            const auto result2 = mutation_cursor1.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(!result2.done);
            REQUIRE(mutation_cursor1.to_last(/*throw_notfound=*/false));
            const auto result3 = mutation_cursor1.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(!result3.done);

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor2.to_first(/*throw_notfound=*/false));
            const auto result4 = mutation_cursor2.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");
            const auto result5 = mutation_cursor2.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "22");
            const auto result6 = mutation_cursor2.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(!result6.done);
            REQUIRE(mutation_cursor2.to_last(/*throw_notfound=*/false));
            const auto result7 = mutation_cursor2.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(!result7.done);
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_last", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (auto [tag, test] : mutation_tests) {
        SECTION(tag + ": to_last on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.to_last(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.to_last(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor1.to_last(/*throw_notfound=*/false));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.to_last(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.to_last(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.to_last(/*throw_notfound=*/false));
        }

        SECTION(tag + ": to_last on existent table: OK") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            const auto result1 = mutation_cursor1.to_last();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMap};
            const auto result2 = mutation_cursor2.to_last(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor3{test->mutation, kTestMap};
            const auto result3 = mutation_cursor3.to_last(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");

            MemoryMutationCursor mutation_cursor4{test->mutation, kTestMultiMap};
            const auto result4 = mutation_cursor4.to_last();
            CHECK(result4.done);
            CHECK(result4.key == "BB");
            CHECK(result4.value == "22");

            MemoryMutationCursor mutation_cursor5{test->mutation, kTestMultiMap};
            const auto result5 = mutation_cursor5.to_last(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "BB");
            CHECK(result5.value == "22");

            MemoryMutationCursor mutation_cursor6{test->mutation, kTestMultiMap};
            const auto result6 = mutation_cursor6.to_last(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "BB");
            CHECK(result6.value == "22");
        }

        SECTION(tag + ": to_last operation is idempotent") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            const auto result1 = mutation_cursor1.to_last();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");
            const auto result2 = mutation_cursor1.to_last();
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMultiMap};
            const auto result3 = mutation_cursor2.to_last();
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "22");
            const auto result4 = mutation_cursor2.to_last();
            CHECK(result4.done);
            CHECK(result4.key == "BB");
            CHECK(result4.value == "22");
        }
    }
}

TEST_CASE("MemoryMutationCursor: current", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (auto [tag, test] : mutation_tests) {
        SECTION(tag + ": current on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.current(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.current(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor1.current(/*throw_notfound=*/false));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.current(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.current(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.current(/*throw_notfound=*/false));
        }

        SECTION(tag + ": current on existent table w/ positioning: OK") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.current();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMap};
            REQUIRE(mutation_cursor2.to_first());
            const auto result2 = mutation_cursor2.current(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");

            MemoryMutationCursor mutation_cursor3{test->mutation, kTestMap};
            REQUIRE(mutation_cursor3.to_first());
            const auto result3 = mutation_cursor3.current(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");

            MemoryMutationCursor mutation_cursor4{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor4.to_first());
            const auto result4 = mutation_cursor4.current();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");

            MemoryMutationCursor mutation_cursor5{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor5.to_first());
            const auto result5 = mutation_cursor5.current(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");

            MemoryMutationCursor mutation_cursor6{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor6.to_first());
            const auto result6 = mutation_cursor6.current(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
        }

        SECTION(tag + ": current operation is idempotent") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kTestMap};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.current();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");
            const auto result2 = mutation_cursor1.current();
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");
            REQUIRE(mutation_cursor1.to_last());
            const auto result3 = mutation_cursor1.current();
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");
            const auto result4 = mutation_cursor1.current();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");

            MemoryMutationCursor mutation_cursor2{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor2.to_first());
            const auto result5 = mutation_cursor2.current();
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");
            const auto result6 = mutation_cursor2.current();
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
            /*REQUIRE(mutation_cursor2.to_last());
            result2 = mutation_cursor2.current();
            check_cursor_result(result2, {"BB", "22"});
            result2 = mutation_cursor2.current();
            check_cursor_result(result2, {"BB", "22"});*/
        }
    }
}

TEST_CASE("MemoryMutationCursor: Next interleaved", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(db::table::kAccountChangeSet);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.1"});
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.3"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(db::table::kAccountChangeSet);
    rw_mem_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.2"});
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.ro_cursor_dup_sort(db::table::kAccountChangeSet);
    auto mem_cursor = test.mutation.ro_cursor_dup_sort(db::table::kAccountChangeSet);

    auto db_result = db_cursor->to_first(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key1");
    CHECK(db_result.value == "value1.1");
    auto mem_result = mem_cursor->to_first(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1.1");

    db_result = db_cursor->to_next(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key1");
    CHECK(db_result.value == "value1.3");
    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1.2");

    db_result = db_cursor->to_next(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key3");
    CHECK(db_result.value == "value3.1");
    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1.3");

    db_result = db_cursor->to_next(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key3");
    CHECK(db_result.value == "value3.3");
    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.1");

    db_result = db_cursor->to_next(/*throw_notfound=*/false);
    CHECK(!db_result.done);
    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.3");

    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(!mem_result.done);
}

TEST_CASE("MemoryMutationCursor: NextDup interleaved", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(db::table::kAccountChangeSet);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.1"});
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.3"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(db::table::kAccountChangeSet);
    rw_mem_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.2"});
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.ro_cursor_dup_sort(db::table::kAccountChangeSet);
    auto mem_cursor = test.mutation.ro_cursor_dup_sort(db::table::kAccountChangeSet);

    auto db_result = db_cursor->to_first(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key1");
    CHECK(db_result.value == "value1.1");
    auto mem_result = mem_cursor->to_first(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1.1");

    db_result = db_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key1");
    CHECK(db_result.value == "value1.3");
    mem_result = mem_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1.2");

    db_result = db_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(!db_result.done);
    mem_result = mem_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1.3");

    db_result = db_cursor->to_next_first_multi(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key3");
    CHECK(db_result.value == "value3.1");
    mem_result = mem_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(!mem_result.done);

    db_result = db_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key3");
    CHECK(db_result.value == "value3.3");
    mem_result = mem_cursor->to_next_first_multi(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.1");

    db_result = db_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(!db_result.done);
    mem_result = mem_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.3");

    mem_result = mem_cursor->to_current_next_multi(/*throw_notfound=*/false);
    CHECK(!mem_result.done);
}

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db
