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

#include "memory_mutation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::db {

const MapConfig kTestMap{"TestTable"};
const MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

const MapConfig kTestNonexistentMap{"NonexistentTable"};

TEST_CASE("MemoryDatabase", "[silkworm][node][db][memory_mutation]") {
    const TemporaryDirectory tmp_dir;

    SECTION("Create a temporary database") {
        CHECK_NOTHROW(MemoryDatabase{});
        CHECK_NOTHROW(MemoryDatabase{tmp_dir.path()});
    }

    SECTION("Create one R/W transaction in a temporary database") {
        MemoryDatabase overlay{tmp_dir.path()};
        ::mdbx::txn_managed rw_txn;
        CHECK_NOTHROW((rw_txn = overlay.start_rw_txn()));
    }

    SECTION("Cannot create more than one R/W transaction in a temporary database") {
        MemoryDatabase overlay{tmp_dir.path()};
        ::mdbx::txn_managed rw_txn;
        CHECK_NOTHROW((rw_txn = overlay.start_rw_txn()));
        CHECK_THROWS_AS(overlay.start_rw_txn(), std::exception);
    }
}

TEST_CASE("MemoryMutation", "[silkworm][node][db][memory_mutation]") {
    const TemporaryDirectory tmp_dir;
    DataDirectory data_dir{tmp_dir.path() / "main_db"};
    data_dir.deploy();
    db::EnvConfig main_db_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .in_memory = true,
    };
    auto main_env{db::open_env(main_db_config)};
    RWTxnManaged main_rw_txn{main_env};

    MemoryOverlay overlay{
        tmp_dir.path(),
        &main_rw_txn,
        [](const std::string& map_name) { return db::MapConfig{map_name.c_str()}; },
        "Sequence",
    };

    SECTION("Create one memory mutation") {
        CHECK_NOTHROW(MemoryMutation{overlay});
    }

    SECTION("Check initial values") {
        MemoryMutation mutation{overlay};
        CHECK_NOTHROW(mutation.external_txn() == &main_rw_txn);
        CHECK_NOTHROW(!mutation.is_table_cleared("TestTable"));
        CHECK_NOTHROW(!mutation.is_entry_deleted("TestTable", Slice{}));
    }

    SECTION("Cannot create two memory mutations") {
        MemoryMutation mutation{overlay};
        CHECK_THROWS_AS(MemoryMutation(overlay), ::mdbx::exception);
    }

    SECTION("Rollback an empty mutation") {
        MemoryMutation mutation{overlay};
        CHECK_NOTHROW(mutation.rollback());
    }

    SECTION("Rollback twice an empty mutation") {
        MemoryMutation mutation{overlay};
        CHECK_NOTHROW(mutation.rollback());
        CHECK_NOTHROW(mutation.rollback());
    }

    SECTION("Check map presence in empty mutation") {
        MemoryMutation mutation{overlay};
        CHECK_NOTHROW(!mutation.has_map(kTestMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestMultiMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestNonexistentMap.name));
    }

    SECTION("Check map presence in nonempty main db") {
        MemoryMutation mutation{overlay};
        open_map(main_rw_txn, kTestMap);
        open_map(main_rw_txn, kTestMultiMap);
        CHECK_NOTHROW(mutation.has_map(kTestMap.name));
        CHECK_NOTHROW(mutation.has_map(kTestMultiMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestNonexistentMap.name));
    }

    SECTION("Check map presence in nonempty mutation") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMap);
        open_map(mutation, kTestMultiMap);
        CHECK_NOTHROW(mutation.has_map(kTestMap.name));
        CHECK_NOTHROW(mutation.has_map(kTestMultiMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestNonexistentMap.name));
    }

    SECTION("Erase key in nonempty mutation") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMap);
        open_map(mutation, kTestMultiMap);

        const auto mutation_cursor = mutation.rw_cursor(kTestMap);
        mutation_cursor->upsert("key1", "value1");
        mutation_cursor->upsert("key2", "value2");
        CHECK(mutation_cursor->seek("key1"));
        CHECK(mutation_cursor->seek("key2"));
        mutation.erase(kTestMap, "key2");
        CHECK(mutation_cursor->seek("key1"));
        CHECK(!mutation_cursor->seek("key2"));

        const auto mutation_cursor_dupsort = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort->upsert("key1", "value1");
        mutation_cursor_dupsort->upsert("key2", "value2");
        CHECK(mutation_cursor_dupsort->seek("key1"));
        CHECK(mutation_cursor_dupsort->seek("key2"));
        mutation.erase(kTestMultiMap, "key2");
        CHECK(mutation_cursor_dupsort->seek("key1"));
        CHECK(!mutation_cursor_dupsort->seek("key2"));
    }
}

}  // namespace silkworm::db
