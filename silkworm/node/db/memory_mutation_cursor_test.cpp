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

// Skip in TSAN build due to false positive w/ lock-order-inversion: https://github.com/google/sanitizers/issues/814
#ifndef SILKWORM_SANITIZE
TEST_CASE("MemoryMutationCursor", "[silkworm][node][db][memory_mutation_cursor]") {
    MemoryMutationCursorTest test;
    test.fill_main_tables();

    SECTION("Create one memory mutation cursor") {
        CHECK_NOTHROW(MemoryMutationCursor{test.mutation, kTestMap});
        CHECK_NOTHROW(MemoryMutationCursor{test.mutation, kTestMultiMap});
    }

    SECTION("Create many memory mutation cursors") {
        std::vector<std::unique_ptr<MemoryMutationCursor>> memory_cursors;
        for (int i{0}; i < 10; ++i) {
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test.mutation, kTestMap)));
            CHECK_NOTHROW(memory_cursors.emplace_back(std::make_unique<MemoryMutationCursor>(test.mutation, kTestMultiMap)));
        }
    }

    SECTION("Check initial values") {
        MemoryMutationCursor mutation_cursor{test.mutation, kTestMap};
        CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
        CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}));
    }

    SECTION("Check predefined tables") {
        for (const auto& table : table::kChainDataTables) {
            MemoryMutationCursor mutation_cursor{test.mutation, table};
            CHECK_NOTHROW(has_map(test.mutation, table.name));
            CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
            CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}));
        }
    }

    SECTION("Empty kTestMap: to_first") {
        MemoryMutationCursor mutation_cursor{test.mutation, kTestMap};
        const auto result = mutation_cursor.to_first();
        CHECK(result);
        if (result) {
            CHECK(result.key == "AA");
            CHECK(result.value == "00");
        }
        CHECK(mutation_cursor.to_first(false));
    }

    test.fill_mutation_tables();

    SECTION("Check tables") {
        for (const auto& table : {kTestMap, kTestMultiMap}) {
            MemoryMutationCursor mutation_cursor{test.mutation, table};
            CHECK_NOTHROW(mutation_cursor.to_first());
            CHECK_NOTHROW(!mutation_cursor.is_table_cleared());
            CHECK_NOTHROW(!mutation_cursor.is_entry_deleted(Slice{}));
        }
    }

    SECTION("Non-empty kTestMap: to_first") {
        MemoryMutationCursor mutation_cursor{test.mutation, kTestMap};
        const auto result = mutation_cursor.to_first();
        CHECK(result);
        if (result) {
            CHECK(result.key == "AA");
            CHECK(result.value == "00");
        }
        CHECK(mutation_cursor.to_first(false));
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db
