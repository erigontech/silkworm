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

#include <catch2/catch.hpp>

#include <silkworm/node/common/directories.hpp>

namespace silkworm::db {

const MapConfig kTestMap{"TestTable"};
const MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

const MapConfig kTestNonexistentMap{"NonexistentTable"};

TEST_CASE("MemoryOverlay", "[silkworm][node][db][memory_mutation]") {
    const TemporaryDirectory tmp_dir;

    SECTION("Create a temporary database") {
        CHECK_NOTHROW(MemoryOverlay{tmp_dir.path()});
    }

    SECTION("Create one R/W transaction in a temporary database") {
        MemoryOverlay overlay{tmp_dir.path()};
        ::mdbx::txn_managed rw_txn;
        CHECK_NOTHROW((rw_txn = overlay.start_rw_tx()));
        CHECK(!rw_txn.env().is_empty());
    }

    SECTION("Cannot create more than one R/W transaction in a temporary database") {
        MemoryOverlay overlay{tmp_dir.path()};
        ::mdbx::txn_managed rw_txn;
        CHECK_NOTHROW((rw_txn = overlay.start_rw_tx()));
        CHECK_THROWS_AS(overlay.start_rw_tx(), std::exception);
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
    RWTxn main_rw_txn{main_env};
    MemoryOverlay overlay{tmp_dir.path()};

    SECTION("Create one memory mutation") {
        CHECK_NOTHROW(MemoryMutation{overlay, &main_rw_txn});
    }

    SECTION("Check initial values") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        CHECK_NOTHROW(mutation.external_txn() == &main_rw_txn);
        CHECK_NOTHROW(!mutation.is_table_cleared("TestTable"));
        CHECK_NOTHROW(!mutation.is_entry_deleted("TestTable", Slice{}));
    }

    SECTION("Cannot create two memory mutations") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        CHECK_THROWS_AS(MemoryMutation(overlay, &main_rw_txn), ::mdbx::exception);
    }

    SECTION("Rollback an empty mutation") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        CHECK_NOTHROW(mutation.rollback());
    }

    SECTION("Rollback twice an empty mutation") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        CHECK_NOTHROW(mutation.rollback());
        CHECK_NOTHROW(mutation.rollback());
    }

    SECTION("Check map presence in empty mutation") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        CHECK_NOTHROW(!mutation.has_map(kTestMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestMultiMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestNonexistentMap.name));
    }

    SECTION("Check map presence in nonempty main db") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        open_map(main_rw_txn, kTestMap);
        open_map(main_rw_txn, kTestMultiMap);
        CHECK_NOTHROW(mutation.has_map(kTestMap.name));
        CHECK_NOTHROW(mutation.has_map(kTestMultiMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestNonexistentMap.name));
    }

    SECTION("Check map presence in nonempty mutation") {
        MemoryMutation mutation{overlay, &main_rw_txn};
        open_map(mutation, kTestMap);
        open_map(mutation, kTestMultiMap);
        CHECK_NOTHROW(mutation.has_map(kTestMap.name));
        CHECK_NOTHROW(mutation.has_map(kTestMultiMap.name));
        CHECK_NOTHROW(!mutation.has_map(kTestNonexistentMap.name));
    }
}

}  // namespace silkworm::db
