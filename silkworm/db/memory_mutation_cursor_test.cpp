// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/datastore/kvdb/memory_mutation_cursor.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>
#include <silkworm/infra/test_util/log.hpp>

namespace silkworm::datastore::kvdb {

using namespace silkworm::db;

static mdbx::env_managed create_main_env(EnvConfig& main_db_config) {
    auto main_env = open_env(main_db_config);
    RWTxnManaged main_txn{main_env};
    table::check_or_create_chaindata_tables(main_txn);
    open_map(main_txn, table::kCode);
    open_map(main_txn, table::kAccountChangeSet);
    main_txn.commit_and_stop();
    return main_env;
}

static void fill_tables(RWTxn& rw_txn) {
    auto rw_cursor1{rw_txn.rw_cursor(table::kCode)};
    rw_cursor1->upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
    rw_cursor1->upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
    auto rw_cursor2{rw_txn.rw_cursor(table::kAccountChangeSet)};
    rw_cursor2->upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
    rw_cursor2->upsert(mdbx::slice{"AA"}, mdbx::slice{"11"});
    rw_cursor2->upsert(mdbx::slice{"AA"}, mdbx::slice{"22"});
    rw_cursor2->upsert(mdbx::slice{"BB"}, mdbx::slice{"22"});
    rw_txn.commit_and_renew();
}

static void alter_tables(RWTxn& rw_txn) {
    auto rw_cursor1{rw_txn.rw_cursor(table::kCode)};
    rw_cursor1->upsert(mdbx::slice{"CC"}, mdbx::slice{"22"});
    auto rw_cursor2{rw_txn.rw_cursor(table::kAccountChangeSet)};
    rw_cursor2->upsert(mdbx::slice{"AA"}, mdbx::slice{"33"});
    rw_cursor2->upsert(mdbx::slice{"BB"}, mdbx::slice{"33"});
    rw_txn.commit_and_renew();
}

class MemoryMutationCursorTest {
  public:
    explicit MemoryMutationCursorTest() {
        open_map(mutation, table::kCode);
        open_map(mutation, table::kAccountChangeSet);
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
    EnvConfig main_db_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .in_memory = true,
    };
    mdbx::env_managed main_env{create_main_env(main_db_config)};
    RWTxnManaged main_txn{main_env};
    MemoryOverlay overlay{tmp_dir.path(), &main_txn, table::get_map_config, table::kSequenceName};
    MemoryMutation mutation{overlay};
};

// Skip in TSAN build due to false positive lock-order-inversion: https://github.com/google/sanitizers/issues/814
#ifndef SILKWORM_SANITIZE

static const MapConfig kNonexistentTestMap{"NonexistentTable"};
static const MapConfig kNonexistentTestMultiMap{"NonexistentMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

TEST_CASE("MemoryMutationCursor: initialization", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    SECTION("Empty overlay: Create memory mutation cursor") {
        // Nonexistent tables
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kNonexistentTestMap});
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, kNonexistentTestMultiMap});

        // Existent tables
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, table::kCode});
        CHECK_NOTHROW(MemoryMutationCursor{test1.mutation, table::kAccountChangeSet});

        // Check initial state
        MemoryMutationCursor mutation_cursor1{test1.mutation, table::kCode};
        CHECK(mutation_cursor1.size() == 2);
        CHECK(!mutation_cursor1.empty());
        CHECK(!mutation_cursor1.is_table_cleared());
        CHECK(!mutation_cursor1.is_entry_deleted(Slice{}, Slice{}));
        MemoryMutationCursor mutation_cursor2{test1.mutation, table::kAccountChangeSet};
        CHECK(mutation_cursor2.size() == 4);
        CHECK(!mutation_cursor2.empty());
        CHECK(!mutation_cursor2.is_table_cleared());
        CHECK(!mutation_cursor2.is_entry_deleted(Slice{}, Slice{}));

        // Create many cursors
        std::vector<std::unique_ptr<MemoryMutationCursor>> memory_cursors;
        for (int i{0}; i < 10; ++i) {
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test1.mutation, table::kCode)));
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test1.mutation, table::kAccountChangeSet)));
        }

        // Check predefined tables
        for (const auto& table : table::kChainDataTables) {
            MemoryMutationCursor mutation_cursor{test1.mutation, table};
            CHECK(has_map(test1.mutation, table.name));
            CHECK(!mutation_cursor.is_table_cleared());
            CHECK(!mutation_cursor.is_entry_deleted(Slice{}, Slice{}));
        }
    }

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    SECTION("Nonempty overlay: Check tables") {
        for (const auto& table : {table::kCode, table::kAccountChangeSet}) {
            MemoryMutationCursor mutation_cursor{test2.mutation, table};
            CHECK_NOTHROW(mutation_cursor.to_first());
            CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
            CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}, Slice{}));
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_first", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
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
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            const auto result1 = mutation_cursor1.to_first();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");
            MemoryMutationCursor mutation_cursor2{test->mutation, table::kCode};
            const auto result2 = mutation_cursor2.to_first(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");
            MemoryMutationCursor mutation_cursor3{test->mutation, table::kCode};
            const auto result3 = mutation_cursor3.to_first(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            const auto result4 = mutation_cursor4.to_first();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            const auto result5 = mutation_cursor5.to_first(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            const auto result6 = mutation_cursor6.to_first(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
        }

        SECTION(tag + ": to_first operation is idempotent") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            const auto result1 = mutation_cursor1.to_first();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");
            const auto result2 = mutation_cursor1.to_first();
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kAccountChangeSet};
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

TEST_CASE("MemoryMutationCursor: to_previous", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
        SECTION(tag + ": to_previous on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.to_previous(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.to_previous(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor1.to_previous(/*throw_notfound=*/false));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.to_previous(), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.to_previous(/*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.to_previous(/*throw_notfound=*/false));
        }

        SECTION(tag + ": to_previous on existent table w/ positioning: OK") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            REQUIRE(mutation_cursor1.to_last());
            const auto result1 = mutation_cursor1.to_previous();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kCode};
            REQUIRE(mutation_cursor2.to_last());
            const auto result2 = mutation_cursor2.to_previous(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");

            MemoryMutationCursor mutation_cursor3{test->mutation, table::kCode};
            REQUIRE(mutation_cursor3.to_last());
            const auto result3 = mutation_cursor3.to_previous(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor4.to_last());
            const auto result4 = mutation_cursor4.to_previous();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "22");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor5.to_last());
            const auto result5 = mutation_cursor5.to_previous(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "22");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor6.to_last());
            const auto result6 = mutation_cursor6.to_previous(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "22");
        }

        SECTION(tag + ": to_previous multiple operations") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            REQUIRE(mutation_cursor1.to_last(/*throw_notfound=*/false));
            const auto result1 = mutation_cursor1.to_previous(/*throw_notfound=*/false);
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");
            const auto result2 = mutation_cursor1.to_previous(/*throw_notfound=*/false);
            CHECK(!result2.done);
            REQUIRE(mutation_cursor1.to_first(/*throw_notfound=*/false));
            const auto result3 = mutation_cursor1.to_previous(/*throw_notfound=*/false);
            CHECK(!result3.done);

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor2.to_last(/*throw_notfound=*/false));
            const auto result4 = mutation_cursor2.to_previous(/*throw_notfound=*/false);
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "22");
            const auto result5 = mutation_cursor2.to_previous(/*throw_notfound=*/false);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "11");
            REQUIRE(mutation_cursor2.to_first(/*throw_notfound=*/false));
            const auto result6 = mutation_cursor2.to_previous(/*throw_notfound=*/false);
            CHECK(!result6.done);
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_next", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
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
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.to_next();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kCode};
            REQUIRE(mutation_cursor2.to_first());
            const auto result2 = mutation_cursor2.to_next(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor3{test->mutation, table::kCode};
            REQUIRE(mutation_cursor3.to_first());
            const auto result3 = mutation_cursor3.to_next(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor4.to_first());
            const auto result4 = mutation_cursor4.to_next();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor5.to_first());
            const auto result5 = mutation_cursor5.to_next(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "11");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor6.to_first());
            const auto result6 = mutation_cursor6.to_next(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "11");
        }

        SECTION(tag + ": to_next multiple operations") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            REQUIRE(mutation_cursor1.to_first(/*throw_notfound=*/false));
            const auto result1 = mutation_cursor1.to_next(/*throw_notfound=*/false);
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");
        }
    }
}

TEST_CASE("MemoryMutationCursor: to_current_next_multi", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
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
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.to_current_next_multi();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kCode};
            REQUIRE(mutation_cursor2.to_first());
            const auto result2 = mutation_cursor2.to_current_next_multi(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor3{test->mutation, table::kCode};
            REQUIRE(mutation_cursor3.to_first());
            const auto result3 = mutation_cursor3.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor4.to_first());
            const auto result4 = mutation_cursor4.to_current_next_multi();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor5.to_first());
            const auto result5 = mutation_cursor5.to_current_next_multi(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "11");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor6.to_first());
            const auto result6 = mutation_cursor6.to_current_next_multi(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "11");
        }

        SECTION(tag + ": to_current_next_multi multiple operations") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
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

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kAccountChangeSet};
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

TEST_CASE("MemoryMutationCursor: to_last", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
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
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            const auto result1 = mutation_cursor1.to_last();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kCode};
            const auto result2 = mutation_cursor2.to_last(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor3{test->mutation, table::kCode};
            const auto result3 = mutation_cursor3.to_last(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            const auto result4 = mutation_cursor4.to_last();
            CHECK(result4.done);
            CHECK(result4.key == "BB");
            CHECK(result4.value == "22");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            const auto result5 = mutation_cursor5.to_last(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "BB");
            CHECK(result5.value == "22");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            const auto result6 = mutation_cursor6.to_last(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "BB");
            CHECK(result6.value == "22");
        }

        SECTION(tag + ": to_last operation is idempotent") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            const auto result1 = mutation_cursor1.to_last();
            CHECK(result1.done);
            CHECK(result1.key == "BB");
            CHECK(result1.value == "11");
            const auto result2 = mutation_cursor1.to_last();
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kAccountChangeSet};
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

TEST_CASE("MemoryMutationCursor: current", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
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
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            REQUIRE(mutation_cursor1.to_first());
            const auto result1 = mutation_cursor1.current();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kCode};
            REQUIRE(mutation_cursor2.to_first());
            const auto result2 = mutation_cursor2.current(/*throw_notfound=*/true);
            CHECK(result2.done);
            CHECK(result2.key == "AA");
            CHECK(result2.value == "00");

            MemoryMutationCursor mutation_cursor3{test->mutation, table::kCode};
            REQUIRE(mutation_cursor3.to_first());
            const auto result3 = mutation_cursor3.current(/*throw_notfound=*/false);
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor4.to_first());
            const auto result4 = mutation_cursor4.current();
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor5.to_first());
            const auto result5 = mutation_cursor5.current(/*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor6.to_first());
            const auto result6 = mutation_cursor6.current(/*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
        }

        SECTION(tag + ": current operation is idempotent") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
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
            CHECK(result3.key == "BB");
            CHECK(result3.value == "11");
            const auto result4 = mutation_cursor1.current();
            CHECK(result4.done);
            CHECK(result4.key == "BB");
            CHECK(result4.value == "11");

            MemoryMutationCursor mutation_cursor2{test->mutation, table::kAccountChangeSet};
            REQUIRE(mutation_cursor2.to_first());
            const auto result5 = mutation_cursor2.current();
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");
            const auto result6 = mutation_cursor2.current();
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
            REQUIRE(mutation_cursor2.to_last());
            const auto result7 = mutation_cursor2.current();
            CHECK(result7.done);
            CHECK(result7.key == "BB");
            CHECK(result7.value == "22");
            const auto result8 = mutation_cursor2.current();
            CHECK(result8.done);
            CHECK(result8.key == "BB");
            CHECK(result8.value == "22");
        }
    }
}

TEST_CASE("MemoryMutationCursor: seek", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
        SECTION(tag + ": seek on nonexistent table: MDBX_NOTFOUND") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK(!mutation_cursor1.seek("k"));

            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK(!mutation_cursor2.seek("k"));
        }

        SECTION(tag + ": seek on existent non-empty table: OK") {
            // Single-value table
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            CHECK(mutation_cursor1.seek("AA"));  // existent key (seek saves value in current)
            const auto result1 = mutation_cursor1.current();
            CHECK(result1.done);
            CHECK(result1.key == "AA");
            CHECK(result1.value == "00");

            CHECK(mutation_cursor1.seek("BB"));  // existent key (seek saves value in current)
            const auto result2 = mutation_cursor1.current();
            CHECK(result2.done);
            CHECK(result2.key == "BB");
            CHECK(result2.value == "11");

            CHECK(!mutation_cursor1.seek("CC"));  // nonexistent key

            // Multi-value table
            MemoryMutationCursor mutation_cursor2{test->mutation, table::kAccountChangeSet};
            CHECK(mutation_cursor2.seek("AA"));  // existent key (seek saves value in current)
            const auto result3 = mutation_cursor2.current();
            CHECK(result3.done);
            CHECK(result3.key == "AA");
            CHECK(result3.value == "00");

            CHECK(mutation_cursor2.seek("BB"));  // existent key (seek saves value in current)
            const auto result4 = mutation_cursor2.current();
            CHECK(result4.done);
            CHECK(result4.key == "BB");
            CHECK(result4.value == "22");
        }
    }

    test1.alter_main_tables();
    test2.alter_mutation_tables();

    for (const auto& [tag, test] : mutation_tests) {
        SECTION(tag + ": seek after alter: OK") {
            // Single-value table
            MemoryMutationCursor mutation_cursor1{test2.mutation, table::kCode};
            CHECK(mutation_cursor1.seek("AA"));  // existent key
            CHECK(mutation_cursor1.seek("BB"));  // existent key
            CHECK(mutation_cursor1.seek("CC"));  // existent key

            // Multi-value table
            MemoryMutationCursor mutation_cursor2{test2.mutation, table::kAccountChangeSet};
            CHECK(mutation_cursor2.seek("AA"));  // existent key
            CHECK(mutation_cursor2.seek("BB"));  // existent key
        }
    }
}

TEST_CASE("MemoryMutationCursor: lower_bound", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
        SECTION(tag + ": lower_bound on nonexistent single-value table: mdbx::incompatible_operation") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.lower_bound("k", /*throw_notfound=*/true), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor1.lower_bound("k"), mdbx::not_found);
        }

        SECTION(tag + ": lower_bound on nonexistent multi-value table: mdbx::not_found") {
            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.lower_bound("k"), mdbx::not_found);
            CHECK_THROWS_AS(mutation_cursor2.lower_bound("k", /*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.lower_bound("k", /*throw_notfound=*/false));
        }

        SECTION(tag + ": lower_bound on existent multi-value table: OK") {
            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            const auto result4 = mutation_cursor4.lower_bound("AA");
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            const auto result5 = mutation_cursor5.lower_bound("AA", /*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            const auto result6 = mutation_cursor6.lower_bound("AA", /*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
        }

        SECTION(tag + ": lower_bound multiple operations") {
            MemoryMutationCursor mutation_cursor{test->mutation, table::kAccountChangeSet};
            const auto result4 = mutation_cursor.lower_bound("AA");
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "00");
            const auto result5 = mutation_cursor.lower_bound("AA");
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "00");
            REQUIRE(mutation_cursor.to_last(/*throw_notfound=*/false));
            const auto result6 = mutation_cursor.lower_bound("AA");
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "00");
        }
    }
}

TEST_CASE("MemoryMutationCursor: lower_bound_multivalue", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;
    test1.fill_main_tables();

    MemoryMutationCursorTest test2;
    test2.fill_main_tables();
    test2.fill_mutation_tables();

    std::map<std::string, MemoryMutationCursorTest*> mutation_tests = {
        {"Empty overlay", &test1},
        {"Nonempty overlay", &test2},
    };
    for (const auto& [tag, test] : mutation_tests) {
        SECTION(tag + ": lower_bound_multivalue on nonexistent single-value table: mdbx::incompatible_operation") {
            MemoryMutationCursor mutation_cursor1{test->mutation, kNonexistentTestMap};
            CHECK_THROWS_AS(mutation_cursor1.lower_bound_multivalue("k", "v", /*throw_notfound=*/true), mdbx::incompatible_operation);
            CHECK_THROWS_AS(mutation_cursor1.lower_bound_multivalue("k", "v"), mdbx::incompatible_operation);
        }

        SECTION(tag + ": lower_bound_multivalue on nonexistent multi-value table: mdbx::not_found") {
            MemoryMutationCursor mutation_cursor2{test->mutation, kNonexistentTestMultiMap};
            CHECK_THROWS_AS(mutation_cursor2.lower_bound_multivalue("k", "v", /*throw_notfound=*/true), mdbx::not_found);
            CHECK(!mutation_cursor2.lower_bound_multivalue("k", "v", /*throw_notfound=*/false));
            CHECK(!mutation_cursor2.lower_bound_multivalue("k", "v"));
        }

        SECTION(tag + ": lower_bound_multivalue on existent multi-value table: OK") {
            MemoryMutationCursor mutation_cursor1{test->mutation, table::kCode};
            CHECK_THROWS_AS(mutation_cursor1.lower_bound_multivalue("BB", "11"), mdbx::incompatible_operation);

            MemoryMutationCursor mutation_cursor4{test->mutation, table::kAccountChangeSet};
            const auto result4 = mutation_cursor4.lower_bound_multivalue("AA", "11");
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");

            MemoryMutationCursor mutation_cursor5{test->mutation, table::kAccountChangeSet};
            const auto result5 = mutation_cursor5.lower_bound_multivalue("AA", "11", /*throw_notfound=*/true);
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "11");

            MemoryMutationCursor mutation_cursor6{test->mutation, table::kAccountChangeSet};
            const auto result6 = mutation_cursor6.lower_bound_multivalue("AA", "11", /*throw_notfound=*/false);
            CHECK(result6.done);
            CHECK(result6.key == "AA");
            CHECK(result6.value == "11");
        }

        SECTION(tag + ": lower_bound_multivalue multiple operations") {
            MemoryMutationCursor mutation_cursor{test->mutation, table::kAccountChangeSet};
            const auto result4 = mutation_cursor.lower_bound_multivalue("AA", "11");
            CHECK(result4.done);
            CHECK(result4.key == "AA");
            CHECK(result4.value == "11");
            const auto result5 = mutation_cursor.lower_bound_multivalue("AA", "22");
            CHECK(result5.done);
            CHECK(result5.key == "AA");
            CHECK(result5.value == "22");
            REQUIRE(mutation_cursor.to_last(/*throw_notfound=*/false));
            const auto result6 = mutation_cursor.lower_bound_multivalue("AA", "33");
            CHECK(!result6.done);
        }
    }
}

TEST_CASE("MemoryMutationCursor: Previous mem->db after find", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor(table::kCode);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1"});
    rw_db_cursor->upsert(mdbx::slice{"key2"}, mdbx::slice{"value2"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor(table::kCode);
    rw_mem_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3"});

    auto db_cursor = test.main_txn.ro_cursor(table::kCode);
    auto mem_cursor = test.mutation.ro_cursor(table::kCode);

    auto db_result = db_cursor->find("key3", /*throw_notfound=*/false);
    CHECK(!db_result.done);
    auto mem_result = mem_cursor->find("key3", /*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3");

    mem_result = mem_cursor->to_previous(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key2");
    CHECK(mem_result.value == "value2");

    mem_result = mem_cursor->to_previous(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1");

    mem_result = mem_cursor->to_previous(/*throw_notfound=*/false);
    CHECK(!mem_result.done);
}

TEST_CASE("MemoryMutationCursor: Next db->mem after find", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor(table::kCode);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1"});
    rw_db_cursor->upsert(mdbx::slice{"key2"}, mdbx::slice{"value2"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor(table::kCode);
    rw_mem_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3"});

    auto db_cursor = test.main_txn.ro_cursor(table::kCode);
    auto mem_cursor = test.mutation.ro_cursor(table::kCode);

    auto db_result = db_cursor->find("key1", /*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key1");
    CHECK(db_result.value == "value1");
    auto mem_result = mem_cursor->find("key1", /*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key1");
    CHECK(mem_result.value == "value1");

    db_result = db_cursor->to_next(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key2");
    CHECK(db_result.value == "value2");
    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key2");
    CHECK(mem_result.value == "value2");

    db_result = db_cursor->to_next(/*throw_notfound=*/false);
    CHECK(!db_result.done);
    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3");

    mem_result = mem_cursor->to_next(/*throw_notfound=*/false);
    CHECK(!mem_result.done);
}

TEST_CASE("MemoryMutationCursor: CursorDupSort Next db->mem->db", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.1"});
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.3"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_mem_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.2"});

    auto db_cursor = test.main_txn.ro_cursor_dup_sort(table::kAccountChangeSet);
    auto mem_cursor = test.mutation.ro_cursor_dup_sort(table::kAccountChangeSet);

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

TEST_CASE("MemoryMutationCursor: NextDup db->mem->db", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.1"});
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.3"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_mem_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.2"});
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.ro_cursor_dup_sort(table::kAccountChangeSet);
    auto mem_cursor = test.mutation.ro_cursor_dup_sort(table::kAccountChangeSet);

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

TEST_CASE("MemoryMutationCursor: SeekBothExact db->mem->db->mem", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_mem_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.1"});
    rw_mem_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.3"});
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.ro_cursor_dup_sort(table::kAccountChangeSet);
    auto mem_cursor = test.mutation.ro_cursor_dup_sort(table::kAccountChangeSet);

    auto db_result = db_cursor->find_multivalue("key2", "value1.2", /*throw_notfound=*/false);
    CHECK(!db_result.done);
    auto mem_result = mem_cursor->find_multivalue("key2", "value1.2", /*throw_notfound=*/false);
    CHECK(!mem_result.done);

    db_result = db_cursor->find_multivalue("key3", "value3.1", /*throw_notfound=*/false);
    CHECK(!db_result.done);
    mem_result = mem_cursor->find_multivalue("key3", "value3.1", /*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.1");

    db_result = db_cursor->find_multivalue("key3", "value3.2", /*throw_notfound=*/false);
    CHECK(!db_result.done);
    mem_result = mem_cursor->find_multivalue("key3", "value3.2", /*throw_notfound=*/false);
    CHECK(!mem_result.done);

    db_result = db_cursor->find_multivalue("key3", "value3.3", /*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "key3");
    CHECK(db_result.value == "value3.3");
    mem_result = mem_cursor->find_multivalue("key3", "value3.3", /*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.3");
}

TEST_CASE("MemoryMutationCursor: SeekBothRange db->mem->db->mem", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(table::kAccountChangeSet);
    rw_mem_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.1"});
    rw_mem_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.3"});
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.ro_cursor_dup_sort(table::kAccountChangeSet);
    auto mem_cursor = test.mutation.ro_cursor_dup_sort(table::kAccountChangeSet);

    // SeekBothRange does exact match of the key, so we find nothing here
    auto db_result = db_cursor->lower_bound_multivalue("key2", "value1.2");
    CHECK(!db_result.done);
    auto mem_result = mem_cursor->lower_bound_multivalue("key2", "value1.2");
    CHECK(!mem_result.done);

    // SeekBothRange does exact match of the key and range match of the value, so we get last value
    db_result = db_cursor->lower_bound_multivalue("key3", "value3.2");
    CHECK(db_result.done);
    CHECK(db_result.key == "key3");
    CHECK(db_result.value == "value3.3");
    mem_result = mem_cursor->lower_bound_multivalue("key3", "value3.2");
    CHECK(mem_result.done);
    CHECK(mem_result.key == "key3");
    CHECK(mem_result.value == "value3.3");
}

TEST_CASE("MemoryMutationCursor: Delete db->mem->db->mem", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;

    auto rw_db_cursor = test.main_txn.rw_cursor_dup_sort(table::kHashedAccounts);
    rw_db_cursor->upsert(mdbx::slice{"key1"}, mdbx::slice{"value1.1"});
    rw_db_cursor->upsert(mdbx::slice{"key3"}, mdbx::slice{"value3.3"});
    test.main_txn.commit_and_renew();

    auto rw_mem_cursor = test.mutation.rw_cursor_dup_sort(table::kHashedAccounts);
    rw_mem_cursor->upsert("key1", "value1.3");
    rw_mem_cursor->upsert("key2", "value2.1");
    rw_mem_cursor->upsert("key3", "value3.1");
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.rw_cursor_dup_sort(table::kHashedAccounts);
    auto mem_cursor = test.mutation.rw_cursor_dup_sort(table::kHashedAccounts);

    mem_cursor->erase(mdbx::slice{"key1"});
    mem_cursor->erase(mdbx::slice{"key3"});

    CHECK(db_cursor->seek("key1"));
    CHECK(db_cursor->seek("key3"));
    CHECK(!mem_cursor->seek("key1"));
    CHECK(mem_cursor->seek("key2"));
    CHECK(!mem_cursor->seek("key3"));

    mem_cursor->erase(mdbx::slice{"key2"});
    CHECK(!mem_cursor->seek("key2"));
}

TEST_CASE("MemoryMutationCursor: upsert+flush+to_last", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test;
    test.fill_main_tables();

    const auto rw_mem_cursor = test.mutation.rw_cursor(table::kCode);
    rw_mem_cursor->upsert("CC", "22");
    test.mutation.commit_and_renew();

    auto db_cursor = test.main_txn.rw_cursor(table::kCode);
    auto mem_cursor = test.mutation.rw_cursor(table::kCode);
    auto db_result = db_cursor->to_last(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "BB");
    CHECK(db_result.value == "11");
    auto mem_result = mem_cursor->to_last(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "CC");
    CHECK(mem_result.value == "22");

    test.mutation.commit_and_stop();
    test.mutation.flush(test.main_txn);
    test.main_txn.commit_and_renew();

    MemoryMutation mutation{test.overlay};
    auto db_ro_cursor = test.main_txn.ro_cursor(table::kCode);
    auto mem_ro_cursor = mutation.ro_cursor(table::kCode);
    db_result = db_ro_cursor->to_last(/*throw_notfound=*/false);
    CHECK(db_result.done);
    CHECK(db_result.key == "CC");
    CHECK(db_result.value == "22");
    mem_result = mem_ro_cursor->to_last(/*throw_notfound=*/false);
    CHECK(mem_result.done);
    CHECK(mem_result.key == "CC");
    CHECK(mem_result.value == "22");
}

TEST_CASE("MemoryMutationCursor: upsert value w/ different one", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;

    SECTION("to_previous") {
        auto rw_cursor1{test1.main_txn.rw_cursor(table::kCode)};  // non dupsort table
        rw_cursor1->upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1->upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        rw_cursor1->upsert(mdbx::slice{"CC"}, mdbx::slice{"22"});
        test1.main_txn.commit_and_renew();

        MemoryMutationCursor mutation_cursor{test1.mutation, table::kCode};
        mutation_cursor.upsert(mdbx::slice{"BB"}, mdbx::slice{"11b"});  // replace (BB,11) with (BB,11b) & memory value > db value

        // searching the new record
        auto result = mutation_cursor.find("BB", /*throw_notfound=*/false);
        CHECK(result.done);
        CHECK(result.key == "BB");
        CHECK(result.value == "11b");

        auto next_result = mutation_cursor.to_previous(/*throw_notfound=*/true);
        CHECK(next_result.done);
        CHECK(next_result.key == "AA");
        CHECK(next_result.value == "00");
    }

    SECTION("to_next") {
        auto rw_cursor1{test1.main_txn.rw_cursor(table::kCode)};  // non dupsort table
        rw_cursor1->upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1->upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        test1.main_txn.commit_and_renew();

        MemoryMutationCursor mutation_cursor{test1.mutation, table::kCode};
        mutation_cursor.upsert(mdbx::slice{"BB"}, mdbx::slice{"11b"});  // replace (BB,11) with (BB,11b) & memory value > db value

        // searching the new record
        auto result = mutation_cursor.find("AA", /*throw_notfound=*/false);
        CHECK(result.done);

        auto next_result = mutation_cursor.to_next(/*throw_notfound=*/true);
        CHECK(next_result.done);
        CHECK(next_result.key == "BB");
        CHECK(next_result.value == "11b");
        const auto next_next_result = mutation_cursor.to_next(/*throw_notfound=*/false);
        CHECK(!next_next_result.done);
    }
}

TEST_CASE("MemoryMutationCursor: update value w/ different one", "[silkworm][node][db][memory_mutation]") {
    MemoryMutationCursorTest test1;

    SECTION("to_previous") {
        auto rw_cursor1{test1.main_txn.rw_cursor(table::kCode)};  // non dupsort table
        rw_cursor1->upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1->upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        rw_cursor1->upsert(mdbx::slice{"CC"}, mdbx::slice{"22"});
        test1.main_txn.commit_and_renew();

        MemoryMutationCursor mutation_cursor{test1.mutation, table::kCode};
        mutation_cursor.update(mdbx::slice{"BB"}, mdbx::slice{"11b"});  // replace (BB,11) with (BB,11b) & memory value > db value

        // searching the new record
        auto result = mutation_cursor.find("BB", /*throw_notfound=*/false);
        CHECK(result.done);
        CHECK(result.key == "BB");
        CHECK(result.value == "11b");

        auto next_result = mutation_cursor.to_previous(/*throw_notfound=*/true);
        CHECK(next_result.done);
        CHECK(next_result.key == "AA");
        CHECK(next_result.value == "00");
    }

    SECTION("to_next") {
        auto rw_cursor1{test1.main_txn.rw_cursor(table::kCode)};  // non dupsort table
        rw_cursor1->upsert(mdbx::slice{"AA"}, mdbx::slice{"00"});
        rw_cursor1->upsert(mdbx::slice{"BB"}, mdbx::slice{"11"});
        test1.main_txn.commit_and_renew();

        MemoryMutationCursor mutation_cursor{test1.mutation, table::kCode};
        mutation_cursor.update(mdbx::slice{"BB"}, mdbx::slice{"11b"});  // replace (BB,11) with (BB,11b) & memory value > db value

        // searching the new record
        auto result = mutation_cursor.find("AA", /*throw_notfound=*/false);
        CHECK(result.done);

        auto next_result = mutation_cursor.to_next(/*throw_notfound=*/true);
        CHECK(next_result.done);
        CHECK(next_result.key == "BB");
        CHECK(next_result.value == "11b");
        const auto next_next_result = mutation_cursor.to_next(/*throw_notfound=*/false);
        CHECK(!next_next_result.done);
    }
}

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::datastore::kvdb
