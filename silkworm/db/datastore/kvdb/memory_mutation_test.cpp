// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "memory_mutation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <silkworm/infra/common/directories.hpp>

namespace silkworm::datastore::kvdb {

static const MapConfig kTestMap{"TestTable"};
static const MapConfig kTestMultiMap{"TestMultiTable", mdbx::key_mode::usual, mdbx::value_mode::multi};

static const MapConfig kTestNonexistentMap{"NonexistentTable"};

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
    EnvConfig main_db_config{
        .path = data_dir.chaindata().path().string(),
        .create = true,
        .in_memory = true,
    };
    auto main_env{open_env(main_db_config)};
    RWTxnManaged main_rw_txn{main_env};

    MemoryOverlay overlay{
        tmp_dir.path(),
        &main_rw_txn,
        [](std::string_view map_name) {
            if (map_name == kTestMap.name) return kTestMap;
            if (map_name == kTestMultiMap.name) return kTestMultiMap;
            return MapConfig{map_name};
        },
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
        const auto mutation_cursor = mutation.rw_cursor(kTestMap);
        mutation_cursor->upsert("key1", "value1");
        mutation_cursor->upsert("key2", "value2");
        CHECK(mutation_cursor->seek("key1"));
        CHECK(mutation_cursor->seek("key2"));
        mutation.erase(kTestMap, "key2");
        CHECK(mutation_cursor->seek("key1"));
        CHECK(!mutation_cursor->seek("key2"));

        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort->upsert("key1", "value1");
        mutation_cursor_dupsort->upsert("key1", "value2");
        CHECK(mutation_cursor_dupsort->seek("key1"));
        mutation.erase(kTestMultiMap, "key1", "value2");
        CHECK(mutation_cursor_dupsort->seek("key1"));
        auto v1 = mutation_cursor_dupsort->find_multivalue("key1", "value1");
        CHECK(v1.done);
        CHECK(v1.key == "key1");
        CHECK(v1.value == "value1");
        CHECK_THROWS(mutation_cursor_dupsort->find_multivalue("key1", "value2", true));
        mutation.erase(kTestMultiMap, "key1", "value1");
        CHECK(!mutation_cursor_dupsort->seek("key1"));
        CHECK_THROWS(mutation_cursor_dupsort->find_multivalue("key1", "value1", true));
        CHECK_THROWS(mutation_cursor_dupsort->find_multivalue("key1", "value2", true));
    }

    SECTION("Check for deleted dup entry") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort->upsert("key1", "value1");
        mutation_cursor_dupsort->upsert("key1", "value2");

        CHECK(mutation_cursor_dupsort->seek("key1"));

        mutation.erase(kTestMultiMap, "key1", "value1");
        CHECK(mutation.is_dup_deleted(kTestMultiMap.name, "key1", "value1"));
        CHECK(!mutation.is_dup_deleted(kTestMultiMap.name, "key1", "value2"));
    }

    SECTION("Check for deleted dup entry - persisted in db") {
        main_rw_txn.rw_cursor_dup_sort(kTestMultiMap)->upsert("key1", "value1");
        main_rw_txn.rw_cursor_dup_sort(kTestMultiMap)->upsert("key1", "value2");
        main_rw_txn.commit_and_renew();

        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort = mutation.ro_cursor_dup_sort(kTestMultiMap);

        CHECK(mutation_cursor_dupsort->seek("key1"));

        mutation.erase(kTestMultiMap, "key1", "value1");

        mutation.commit_and_stop();
        mutation.flush(main_rw_txn);
        main_rw_txn.commit_and_renew();

        auto cursor2 = main_rw_txn.ro_cursor_dup_sort(kTestMultiMap);
        CHECK_THROWS(cursor2->find_multivalue("key1", "value1", true));
        cursor2->find_multivalue("key1", "value2", true);
    }

    SECTION("Deleted dup entry removed after upserting again") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort->upsert("key1", "value1");
        mutation_cursor_dupsort->upsert("key1", "value2");

        mutation.erase(kTestMultiMap, "key1", "value1");
        CHECK(mutation.is_dup_deleted(kTestMultiMap.name, "key1", "value1"));
        CHECK(!mutation.is_dup_deleted(kTestMultiMap.name, "key1", "value2"));

        mutation_cursor_dupsort->upsert("key1", "value1");
        CHECK(!mutation.is_dup_deleted(kTestMultiMap.name, "key1", "value1"));
        CHECK(!mutation.is_dup_deleted(kTestMultiMap.name, "key1", "value2"));
    }

    SECTION("Find dup entry after deletion first value") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort->upsert("key1", "value1");
        mutation_cursor_dupsort->upsert("key1", "value2");

        auto result1a = mutation_cursor_dupsort->find_multivalue("key1", "value1", false);
        CHECK(result1a.done);
        CHECK(result1a.key == "key1");
        CHECK(result1a.value == "value1");

        auto result2a = mutation_cursor_dupsort->find_multivalue("key1", "value2", false);
        CHECK(result2a.done);
        CHECK(result2a.key == "key1");
        CHECK(result2a.value == "value2");

        mutation.erase(kTestMultiMap, "key1", "value1");

        auto result1b = mutation_cursor_dupsort->find_multivalue("key1", "value1", false);
        CHECK(!result1b.done);

        auto result2b = mutation_cursor_dupsort->find_multivalue("key1", "value2", false);
        CHECK(result2b.done);
        CHECK(result2b.key == "key1");
        CHECK(result2b.value == "value2");
    }

    SECTION("Find dup entry after deletion second value") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort->upsert("key1", "value1");
        mutation_cursor_dupsort->upsert("key1", "value2");

        auto result1a = mutation_cursor_dupsort->find_multivalue("key1", "value1", false);
        CHECK(result1a.done);
        CHECK(result1a.key == "key1");
        CHECK(result1a.value == "value1");

        auto result2a = mutation_cursor_dupsort->find_multivalue("key1", "value2", false);
        CHECK(result2a.done);
        CHECK(result2a.key == "key1");
        CHECK(result2a.value == "value2");

        mutation.erase(kTestMultiMap, "key1", "value2");

        auto result1b = mutation_cursor_dupsort->find_multivalue("key1", "value1", false);
        CHECK(result1b.done);

        auto result2b = mutation_cursor_dupsort->find_multivalue("key1", "value2", false);
        CHECK(!result2b.done);
    }

    SECTION("Find dup entry after deletion using another cursor") {
        MemoryMutation mutation{overlay};
        open_map(mutation, kTestMultiMap);
        const auto mutation_cursor_dupsort1 = mutation.rw_cursor_dup_sort(kTestMultiMap);
        mutation_cursor_dupsort1->upsert("key1", "value1");
        mutation_cursor_dupsort1->upsert("key1", "value2");

        auto result1a = mutation_cursor_dupsort1->find_multivalue("key1", "value1", false);
        CHECK(result1a.done);

        auto result2a = mutation_cursor_dupsort1->find_multivalue("key1", "value2", false);
        CHECK(result2a.done);

        mutation.erase(kTestMultiMap, "key1", "value2");
        mutation.commit_and_stop();
        mutation.flush(main_rw_txn);

        mutation.reopen();

        const auto mutation_cursor_dupsort2 = mutation.rw_cursor_dup_sort(kTestMultiMap);
        auto result1b = mutation_cursor_dupsort2->find_multivalue("key1", "value1", false);
        CHECK(result1b.done);

        auto result2b = mutation_cursor_dupsort2->find_multivalue("key1", "value2", false);
        CHECK(!result2b.done);
    }
}

}  // namespace silkworm::datastore::kvdb
