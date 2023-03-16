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

using Pair = mdbx::pair;

static void check_cursor_result(CursorResult result, Pair kv_pair) {
    CHECK(result);
    if (result) {
        CHECK(result.key == kv_pair.key);
        CHECK(result.value == kv_pair.value);
    }
}

TEST_CASE("MemoryMutationCursor: initialization", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    SECTION("Empty overlay: Create memory mutation cursor for non-existent tables") {
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kNonexistentTestMap});
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kNonexistentTestMultiMap});
    }

    SECTION("Empty overlay: Create one memory mutation cursor") {
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kTestMap});
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kTestMultiMap});
    }

    SECTION("Empty overlay: Create many memory mutation cursors") {
        std::vector<std::unique_ptr<MemoryMutationCursor>> memory_cursors;
        for (int i{0}; i < 10; ++i) {
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test1.mutation, kTestMap)));
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test1.mutation, kTestMultiMap)));
        }
    }

    SECTION("Empty overlay: Check initial values") {
        MemoryMutationCursor mutation_cursor{test1.mutation, kTestMap};
        CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
        CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}));
    }

    SECTION("Empty overlay: Check predefined tables") {
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
        SECTION(tag + ": Nonexistent single-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor.to_first(), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent single-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor.to_first(/*throw_notfound=*/true), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent multi-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK(!mutation_cursor.to_first(/*throw_notfound=*/false));
        }

        SECTION(tag + ": Nonexistent multi-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor.to_first(), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent multi-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor.to_first(/*throw_notfound=*/true), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent single-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK(!mutation_cursor.to_first(/*throw_notfound=*/false));
        }

        SECTION(tag + ": Single-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            const auto result = mutation_cursor.to_first();
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Single-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            const auto result = mutation_cursor.to_first(/*throw_notfound=*/true);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            const auto result = mutation_cursor.to_first(/*throw_notfound=*/false);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            const auto result = mutation_cursor.to_first();
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            const auto result = mutation_cursor.to_first(/*throw_notfound=*/true);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Single-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            const auto result = mutation_cursor.to_first(/*throw_notfound=*/false);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Single-value table: operation is idempotent") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            auto result = mutation_cursor.to_first();
            check_cursor_result(result, {"AA", "00"});
            result = mutation_cursor.to_first();
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table: operation is idempotent") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            auto result = mutation_cursor.to_first();
            check_cursor_result(result, {"AA", "00"});
            result = mutation_cursor.to_first();
            check_cursor_result(result, {"AA", "00"});
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
        SECTION(tag + ": Nonexistent single-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor.to_last(), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent single-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor.to_last(/*throw_notfound=*/true), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent multi-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK(!mutation_cursor.to_last(/*throw_notfound=*/false));
        }

        SECTION(tag + ": Nonexistent multi-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor.to_last(), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent multi-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor.to_last(/*throw_notfound=*/true), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent single-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK(!mutation_cursor.to_last(/*throw_notfound=*/false));
        }

        SECTION(tag + ": Single-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            const auto result = mutation_cursor.to_last();
            check_cursor_result(result, {"BB", "11"});
        }

        SECTION(tag + ": Single-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            const auto result = mutation_cursor.to_last(/*throw_notfound=*/true);
            check_cursor_result(result, {"BB", "11"});
        }

        SECTION(tag + ": Multi-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            const auto result = mutation_cursor.to_last(/*throw_notfound=*/false);
            check_cursor_result(result, {"BB", "11"});
        }

        SECTION(tag + ": Multi-value table") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            const auto result = mutation_cursor.to_last();
            check_cursor_result(result, {"BB", "22"});
        }

        SECTION(tag + ": Multi-value table: throw_notfound=true") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            const auto result = mutation_cursor.to_last(/*throw_notfound=*/true);
            check_cursor_result(result, {"BB", "22"});
        }

        SECTION(tag + ": Multi-value table: throw_notfound=false") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            const auto result = mutation_cursor.to_last(/*throw_notfound=*/false);
            check_cursor_result(result, {"BB", "22"});
        }

        SECTION(tag + ": Single-value table: operation is idempotent") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            auto result = mutation_cursor.to_last();
            check_cursor_result(result, {"BB", "11"});
            result = mutation_cursor.to_last();
            check_cursor_result(result, {"BB", "11"});
        }

        SECTION(tag + ": Multi-value table: operation is idempotent") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            auto result = mutation_cursor.to_last();
            check_cursor_result(result, {"BB", "22"});
            /*result = mutation_cursor.to_last();
            check_cursor_result(result, {"BB", "22"});*/
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
        SECTION(tag + ": Nonexistent single-value table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor.current(), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent single-value table (throw_notfound=true): MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor.current(/*throw_notfound=*/true), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent multi-value table (throw_notfound=false)") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMap};
            CHECK(!mutation_cursor.current(/*throw_notfound=*/false));
        }

        SECTION(tag + ": Nonexistent multi-value table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor.current(), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent multi-value table (throw_notfound=true): MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor.current(/*throw_notfound=*/true), mdbx::not_found);
        }

        SECTION(tag + ": Nonexistent single-value table (throw_notfound=false)") {
            MemoryMutationCursor mutation_cursor{test->mutation, kNonexistentTestMultiMap};
            CHECK(!mutation_cursor.current(/*throw_notfound=*/false));
        }

        SECTION(tag + ": Single-value table after positioning: OK") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            REQUIRE(mutation_cursor.to_first());
            const auto result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Single-value table (throw_notfound=true) after positioning: OK") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            REQUIRE(mutation_cursor.to_first());
            const auto result = mutation_cursor.current(/*throw_notfound=*/true);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table (throw_notfound=false) after positioning: OK") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            REQUIRE(mutation_cursor.to_first());
            const auto result = mutation_cursor.current(/*throw_notfound=*/false);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table after positioning: OK") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor.to_first());
            const auto result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table (throw_notfound=true) after positioning: OK") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor.to_first());
            const auto result = mutation_cursor.current(/*throw_notfound=*/true);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table (throw_notfound=false) after positioning: OK") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor.to_first());
            const auto result = mutation_cursor.current(/*throw_notfound=*/false);
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Single-value table: operation is idempotent") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMap};
            REQUIRE(mutation_cursor.to_first());
            auto result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
            result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
            REQUIRE(mutation_cursor.to_last());
            result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
            result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
        }

        SECTION(tag + ": Multi-value table: operation is idempotent") {
            MemoryMutationCursor mutation_cursor{test->mutation, kTestMultiMap};
            REQUIRE(mutation_cursor.to_first());
            auto result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
            result = mutation_cursor.current();
            check_cursor_result(result, {"AA", "00"});
            /*REQUIRE(mutation_cursor.to_last());
            result = mutation_cursor.current();
            check_cursor_result(result, {"BB", "22"});
            result = mutation_cursor.current();
            check_cursor_result(result, {"BB", "22"});*/
        }
    }
}

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db
