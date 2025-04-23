// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <atomic>
#include <future>
#include <map>
#include <thread>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/test_util/temp_chain_data.hpp>

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

namespace silkworm::datastore::kvdb {

using namespace silkworm::db;

TEST_CASE("Environment opening") {
    SECTION("Default page size on creation") {
        const TemporaryDirectory tmp_dir;
        EnvConfig db_config{
            .path = tmp_dir.path().string(),
            .create = true,
            .in_memory = true,
        };
        REQUIRE(db_config.page_size == os::page_size());
        const auto env{open_env(db_config)};
        CHECK(env.get_pagesize() == db_config.page_size);
    }

    SECTION("Non default page size on creation") {
        const TemporaryDirectory tmp_dir;
        EnvConfig db_config{
            .path = tmp_dir.path().string(),
            .create = true,
            .in_memory = true,
            .page_size = os::page_size() / 2,
        };
        const auto env{open_env(db_config)};
        CHECK(env.get_pagesize() == db_config.page_size);
    }

    SECTION("Read page size on opening") {
        const TemporaryDirectory tmp_dir;
        {
            EnvConfig db_config{
                .path = tmp_dir.path().string(),
                .create = true,
                .in_memory = true,
                .page_size = os::page_size() / 2,
            };
            (void)open_env(db_config);
        }

        {
            // Try to reopen same db with another page size
            EnvConfig db_config{
                .path = tmp_dir.path().string(),
                .create = false,
                .in_memory = true,
                .page_size = os::page_size() * 2,
            };
            const auto env{open_env(db_config)};
            CHECK(env.get_pagesize() == os::page_size() / 2);
        }
    }
}

TEST_CASE("Cursor") {
    const TemporaryDirectory tmp_dir;
    EnvConfig db_config{.path = tmp_dir.path().string(), .create = true, .in_memory = true};
    auto env{open_env(db_config)};

    const MapConfig map_config{"GeneticCode"};

    {
        auto rw_txn{env.start_write()};
        CHECK(list_maps(rw_txn).empty());
        (void)open_map(rw_txn, map_config);
        rw_txn.commit();
    }

    auto txn{env.start_read()};

    const auto& map_names = list_maps(txn);
    CHECK(map_names.size() == 1);
    CHECK(map_names[0] == "GeneticCode");

    // A bit of explanation here:
    // Cursors cache may get polluted by previous tests or is empty
    // in case this is the only test being executed. So we can't rely
    // on empty() property rather we must evaluate deltas.
    size_t original_cache_size{PooledCursor::handles_cache().size()};

    {
        PooledCursor cursor1(txn, map_config);
        if (original_cache_size) {
            // One handle pulled from cache
            REQUIRE(PooledCursor::handles_cache().size() == original_cache_size - 1);
        } else {
            // A new handle has been created
            REQUIRE(PooledCursor::handles_cache().size() == original_cache_size);
        }
        REQUIRE(cursor1.get_map_stat().ms_entries == 0);
    }

    // After destruction of previous cursor cache has increased by one if it was originally empty, otherwise it is
    // restored to its original size
    if (!original_cache_size) {
        REQUIRE(PooledCursor::handles_cache().size() == original_cache_size + 1);
    } else {
        REQUIRE(PooledCursor::handles_cache().size() == original_cache_size);
    }

    txn.abort();
    txn = env.start_write();
    PooledCursor broken(txn, {"Test"});

    // Force exceed of cache size
    std::vector<PooledCursor> cursors;
    const size_t new_cache_size = original_cache_size + 5;
    cursors.reserve(new_cache_size);
    for (size_t i = 0; i < new_cache_size; ++i) {
        cursors.emplace_back(txn, map_config);
    }
    REQUIRE(PooledCursor::handles_cache().empty() == true);
    cursors.clear();
    REQUIRE(PooledCursor::handles_cache().empty() == false);
    REQUIRE(PooledCursor::handles_cache().size() == new_cache_size);

    PooledCursor cursor2(PooledCursor(txn, {"test"}));
    REQUIRE(cursor2.operator bool() == true);
    PooledCursor cursor3 = std::move(cursor2);
    // REQUIRE(cursor2.operator bool() == false);
    REQUIRE(cursor3.operator bool() == true);

    txn.commit();

    // In another thread cursor cache must be empty
    std::atomic<size_t> other_thread_size1{0};
    std::atomic<size_t> other_thread_size2{0};
    std::thread t([&other_thread_size1, &other_thread_size2, &env]() {
        auto thread_txn{env.start_write()};
        { PooledCursor cursor(thread_txn, {"Test"}); }
        other_thread_size1 = PooledCursor::handles_cache().size();

        // Pull a handle from the pool and close the cursor directly
        // so is not returned to the pool
        PooledCursor cursor(thread_txn, {"Test"});
        cursor.close();
        other_thread_size2 = PooledCursor::handles_cache().size();
    });
    t.join();
    REQUIRE(other_thread_size1 == 1);
    REQUIRE(other_thread_size2 == 0);
}

TEST_CASE("ROAccess/RWAccess ::mdbx::env lifecycle") {
    const TemporaryDirectory tmp_dir;
    EnvConfig db_config{.path = tmp_dir.path().string(), .create = true, .in_memory = true};
    auto env{open_env(db_config)};

    SECTION("ROAccess") {
        std::unique_ptr<ROAccess> access;
        {
            // Create ROAccess with env_copy lvalue that gets destroyed immediately after
            ::mdbx::env env_copy{env};  // NOLINT(cppcoreguidelines-slicing)
            access = std::make_unique<ROAccess>(env_copy);
        }
        // env is still alive so using access *must* be safe
        CHECK(access->operator*().get_path() == env.get_path());
    }
    SECTION("RWAccess") {
        std::unique_ptr<RWAccess> access;
        {
            // Create RWAccess with env_copy lvalue that gets destroyed immediately after
            ::mdbx::env env_copy{env};  // NOLINT(cppcoreguidelines-slicing)
            access = std::make_unique<RWAccess>(env_copy);
        }
        // env is still alive so using access *must* be safe
        CHECK(access->operator*().get_path() == env.get_path());
    }
}

TEST_CASE("RWTxn") {
    const TemporaryDirectory tmp_dir;
    EnvConfig db_config{.path = tmp_dir.path().string(), .create = true, .in_memory = true};
    auto env{open_env(db_config)};
    static constexpr std::string_view kTableName{"GeneticCode"};

    SECTION("Managed: commit_and_renew") {
        {
            auto tx{RWTxnManaged(env)};
            PooledCursor table_cursor(*tx, {kTableName});

            // populate table
            for (const auto& [key, value] : kGeneticCode) {
                table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
            }

            tx.commit_and_renew();
        }

        auto tx{env.start_read()};
        PooledCursor table_cursor(tx, {kTableName});
        REQUIRE(table_cursor.empty() == false);
    }

    SECTION("Managed: commit_and_stop") {
        {
            auto tx{RWTxnManaged(env)};
            PooledCursor table_cursor(*tx, {kTableName});

            // populate table
            for (const auto& [key, value] : kGeneticCode) {
                table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
            }

            tx.commit_and_stop();
        }

        auto tx{env.start_read()};
        PooledCursor table_cursor(tx, {kTableName});
        REQUIRE(table_cursor.empty() == false);
    }

    SECTION("External: commit_and_renew") {
        RWTxnManaged tx{env};
        tx.disable_commit();
        {
            (void)tx->create_map(std::string{kTableName}, mdbx::key_mode::usual, mdbx::value_mode::single);
            tx.commit_and_renew();  // Does not have any effect
        }
        tx.abort();
        RWTxnManaged tx2{env};
        REQUIRE(has_map(tx2, kTableName) == false);
    }

    SECTION("External: commit_and_stop") {
        RWTxnManaged tx{env};
        tx.disable_commit();
        {
            (void)tx->create_map(std::string{kTableName}, mdbx::key_mode::usual, mdbx::value_mode::single);
            tx.commit_and_stop();  // Does not have any effect
        }
        tx.abort();
        RWTxnManaged tx2{env};
        REQUIRE(has_map(tx2, kTableName) == false);
    }

    SECTION("Cursor from RWTxn") {
        auto tx{RWTxnManaged(env)};
        PooledCursor table_cursor(tx, {kTableName});
        REQUIRE(table_cursor.empty());
        REQUIRE_NOTHROW(table_cursor.bind(tx, {kTableName}));
        table_cursor.close();
        REQUIRE_THROWS(table_cursor.bind(tx, {kTableName}));
    }

    SECTION("Unmanaged: commit_and_renew") {
        {
            ::MDBX_txn* rw_txn{nullptr};
            ::mdbx::error::success_or_throw(::mdbx_txn_begin(env, nullptr, MDBX_TXN_READWRITE, &rw_txn));

            auto tx{RWTxnUnmanaged(rw_txn)};
            PooledCursor table_cursor(*tx, {kTableName});

            // populate table
            for (const auto& [key, value] : kGeneticCode) {
                table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
            }

            CHECK_THROWS_AS(tx.commit_and_renew(), std::runtime_error);

            ::mdbx::error::success_or_throw(::mdbx_txn_commit(rw_txn));
        }
        auto ro_txn{env.start_read()};
        PooledCursor cursor(ro_txn, {kTableName});
        CHECK(cursor.empty() == false);
    }

    SECTION("Unmanaged: commit_and_stop") {
        {
            ::MDBX_txn* rw_txn{nullptr};
            ::mdbx::error::success_or_throw(::mdbx_txn_begin(env, nullptr, MDBX_TXN_READWRITE, &rw_txn));

            auto tx{RWTxnUnmanaged(rw_txn)};
            PooledCursor table_cursor(*tx, {kTableName});

            // populate table
            for (const auto& [key, value] : kGeneticCode) {
                table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
            }

            CHECK_THROWS_AS(tx.commit_and_stop(), std::runtime_error);

            ::mdbx::error::success_or_throw(::mdbx_txn_commit(rw_txn));
        }
        auto ro_txn{env.start_read()};
        PooledCursor cursor(ro_txn, {kTableName});
        CHECK(cursor.empty() == false);
    }
}

TEST_CASE("Cursor walk") {
    const TemporaryDirectory tmp_dir;
    EnvConfig db_config{.path = tmp_dir.path().string(), .create = true, .in_memory = true};
    auto env{open_env(db_config)};
    auto txn{env.start_write()};

    static constexpr std::string_view kTableName{"GeneticCode"};

    PooledCursor table_cursor(txn, {kTableName});

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

        // Reset cursor so its position is at the begining
        table_cursor.to_first();

        // read entire table forward
        cursor_for_each(table_cursor, save_all_data_map);
        CHECK(data_map == kGeneticCode);
        data_map.clear();

        // read entire table backwards
        table_cursor.bind(txn, {kTableName});
        cursor_for_each(table_cursor, save_all_data_map, CursorMoveDirection::kReverse);
        CHECK(data_map == kGeneticCode);
        data_map.clear();

        // Ensure the order is reversed
        table_cursor.bind(txn, {kTableName});
        cursor_for_each(table_cursor, save_all_data_vec, CursorMoveDirection::kReverse);
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
        cursor_for_count(table_cursor, save_all_data_map, /*max_count=*/4, CursorMoveDirection::kReverse);
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
        table_cursor.bind(txn, {kTableName});
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
        table_cursor.bind(txn, {kTableName});
        cursor_erase(table_cursor, set_key, CursorMoveDirection::kReverse);
        REQUIRE(txn.get_map_stat(table_cursor.map()).ms_entries == 0);

        // populate table
        for (const auto& [key, value] : kGeneticCode) {
            table_cursor.upsert(mdbx::slice{key}, mdbx::slice{value});
        }

        // Erase backwards from "CAA"
        set_key[0] = 'C';
        set_key[1] = 'A';
        set_key[2] = 'A';
        cursor_erase(table_cursor, set_key, CursorMoveDirection::kReverse);
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.begin()->second == "Glutamine");

        // Erase forward from "UAA"
        set_key[0] = 'U';
        set_key[1] = 'A';
        set_key[2] = 'A';
        cursor_erase(table_cursor, set_key, CursorMoveDirection::kForward);
        data_map.clear();
        cursor_for_each(table_cursor, save_all_data_map);
        REQUIRE(data_map.rbegin()->second == "Valine");
    }
}

//! Compute the maximum free space in an empty MDBX database page
//! \warning this may change in future versions of MDBX
//! \details see `page_space` function in MDBX core.c
static size_t page_space(const mdbx::txn& txn) {
    constexpr size_t kPageHeaderSize{20};  // size of MDBX page header (PAGEHDRSZ)
    const auto stats = txn.env().get_stat(txn);
    const size_t db_page_size{stats.ms_psize};
    return db_page_size - kPageHeaderSize;
}

static size_t max_multivalue_size_for_leaf_page(const mdbx::txn& txn) {
    constexpr size_t kDupSortNodes{2};
    constexpr size_t kNodeHeaderSize{8};  // size of MDBX node header (NODESIZE)
    return page_space(txn) / kDupSortNodes - 2 * kNodeHeaderSize;
}

TEST_CASE("OF pages") {
    test_util::TempChainData context;
    RWTxn& txn = context.rw_txn();

    SECTION("Single-value map: No overflow") {
        PooledCursor target(txn, table::kAccountHistory);
        Bytes key(20, '\0');
        Bytes value(max_value_size_for_leaf_page(*txn, key.size()), '\0');
        target.insert(to_slice(key), to_slice(value));
        txn.commit_and_renew();
        target.bind(txn, table::kAccountHistory);
        auto stats{target.get_map_stat()};
        CHECK(stats.ms_overflow_pages == 0);
    }

    SECTION("Single-value map: Let's overflow") {
        PooledCursor target(txn, table::kAccountHistory);
        Bytes key(20, '\0');
        Bytes value(max_value_size_for_leaf_page(*txn, key.size()) + /*any extra value*/ 1, '\0');
        target.insert(to_slice(key), to_slice(value));
        txn.commit_and_renew();
        target.bind(txn, table::kAccountHistory);
        auto stats{target.get_map_stat()};
        CHECK(stats.ms_overflow_pages > 0);
    }

    SECTION("Multi-value map: No overflow, value size OK") {
        PooledCursor target(txn, table::kPlainState);
        Bytes key(20, '\0');
        Bytes value(max_multivalue_size_for_leaf_page(txn), '\0');
        target.insert(to_slice(key), to_slice(value));
        txn.commit_and_renew();
        target.bind(txn, table::kPlainState);
        auto stats{target.get_map_stat()};
        CHECK(stats.ms_overflow_pages == 0);
    }

    // Skip the following section in debug as too big data size in multi-value map will assert
#ifdef NDEBUG
    SECTION("Multi-value map: No overflow, error for value too big") {
        PooledCursor target(txn, table::kPlainState);
        Bytes key(20, '\0');
        Bytes value(max_multivalue_size_for_leaf_page(txn) + /*any extra value*/ 1, '\0');
        CHECK_THROWS_AS(target.insert(to_slice(key), to_slice(value)), ::mdbx::exception);
    }
#endif  // NDEBUG
}

static uint64_t get_free_pages(const ::mdbx::env& env) {
    uint64_t free_pages{0};

    // Use threaded execution because MDBX does not allow overlapping txns in same thread
    std::async([&]() {
        constexpr MDBX_dbi kFreeDbi{0};
        ::mdbx::map_handle free_map{kFreeDbi};

        auto ro_txn{env.start_read()};
        auto free_cursor{ro_txn.open_cursor(free_map)};
        auto data = free_cursor.to_first(false);
        while (data.done) {
            size_t tx_id{0};
            std::memcpy(&tx_id, from_slice(data.key).data(), sizeof(size_t));
            uint32_t tx_free_pages{0};
            std::memcpy(&tx_free_pages, from_slice(data.value).data(), sizeof(uint32_t));
            free_pages += tx_free_pages;
            data = free_cursor.to_next(false);
        }
    }).get();

    return free_pages;
}

TEST_CASE("Single-value erase+upsert w/ same value increases free pages") {
    TemporaryDirectory tmp_dir{};
    auto data_directory{std::make_unique<DataDirectory>(tmp_dir.path(), /*create=*/true)};
    EnvConfig env_config{
        .path = data_directory->chaindata().path().string(),
        .create = true,
        .readonly = false,
        .exclusive = false,
        .in_memory = true,
    };
    auto env{open_env(env_config)};

    constexpr size_t kKeySize{20};  // just to copycat account address size
    const Bytes key(kKeySize, '\0');

    // Initialize the map content w/ one max-size value [scope needed to limit rw_txn lifecycle]
    {
        auto rw_txn{env.start_write()};
        auto code_map{open_map(rw_txn, table::kCode)};
        auto code_stats{rw_txn.get_map_stat(code_map)};
        REQUIRE(code_stats.ms_entries == 0);
        REQUIRE(code_stats.ms_depth == 0);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 0);
        REQUIRE(code_stats.ms_overflow_pages == 0);
        auto code_cursor{rw_txn.open_cursor(code_map)};
        Bytes value(max_value_size_for_leaf_page(rw_txn, key.size()), static_cast<uint8_t>(10));
        code_cursor.insert(to_slice(key), to_slice(value));  // insert or upsert equivalent here
        code_stats = rw_txn.get_map_stat(code_map);
        REQUIRE(code_stats.ms_entries == 1);  // we have 1 value here
        REQUIRE(code_stats.ms_depth == 1);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 1);  // we have 1 max data value
        REQUIRE(code_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 0);  // No free pages after initialization
    }

    SECTION("upsert same value does not cause any free page") {
        auto rw_txn{env.start_write()};
        auto code_map{open_map(rw_txn, table::kCode)};
        auto code_cursor{rw_txn.open_cursor(code_map)};
        auto key_slice{to_slice(key)};
        Bytes value(max_value_size_for_leaf_page(rw_txn, key.size()), static_cast<uint8_t>(10));
        auto value_slice{to_slice(value)};
        code_cursor.upsert(key_slice, value_slice);
        auto code_stats{rw_txn.get_map_stat(code_map)};
        REQUIRE(code_stats.ms_entries == 1);
        REQUIRE(code_stats.ms_depth == 1);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 1);
        REQUIRE(code_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 0);  // no free page produced
    }

    SECTION("erase + upsert same value causes two free pages") {
        auto rw_txn{env.start_write()};
        auto code_map{open_map(rw_txn, table::kCode)};
        auto code_cursor{rw_txn.open_cursor(code_map)};
        auto key_slice{to_slice(key)};
        CHECK(code_cursor.erase(key_slice));
        Bytes value(max_value_size_for_leaf_page(rw_txn, key.size()), static_cast<uint8_t>(10));
        auto value_slice{to_slice(value)};
        code_cursor.upsert(key_slice, value_slice);
        auto code_stats{rw_txn.get_map_stat(code_map)};
        REQUIRE(code_stats.ms_entries == 1);
        REQUIRE(code_stats.ms_depth == 1);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 1);
        REQUIRE(code_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages if we erase+upsert w/ same value => bad pattern
    }

    SECTION("upsert different value causes two free pages") {
        auto rw_txn{env.start_write()};
        auto code_map{open_map(rw_txn, table::kCode)};
        auto code_cursor{rw_txn.open_cursor(code_map)};
        auto key_slice{to_slice(key)};
        Bytes value(max_value_size_for_leaf_page(rw_txn, key.size()), static_cast<uint8_t>(11));
        auto value_slice{to_slice(value)};
        code_cursor.upsert(key_slice, value_slice);
        auto code_stats{rw_txn.get_map_stat(code_map)};
        REQUIRE(code_stats.ms_entries == 1);  // we have 1 value here since table is single-value
        REQUIRE(code_stats.ms_depth == 1);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 1);  // we have 1 max data value
        REQUIRE(code_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages in any case
    }

    SECTION("erase + upsert different value causes two free pages") {
        auto rw_txn{env.start_write()};
        auto code_map{open_map(rw_txn, table::kCode)};
        auto code_cursor{rw_txn.open_cursor(code_map)};
        auto key_slice{to_slice(key)};
        CHECK(code_cursor.erase(key_slice, true));
        Bytes value(max_value_size_for_leaf_page(rw_txn, key.size()), static_cast<uint8_t>(11));
        auto value_slice{to_slice(value)};
        code_cursor.upsert(key_slice, value_slice);
        auto code_stats{rw_txn.get_map_stat(code_map)};
        REQUIRE(code_stats.ms_entries == 1);
        REQUIRE(code_stats.ms_depth == 1);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 1);
        REQUIRE(code_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages in any case
    }

    SECTION("erase causes two free pages") {
        auto rw_txn{env.start_write()};
        auto code_map{open_map(rw_txn, table::kCode)};
        auto code_cursor{rw_txn.open_cursor(code_map)};
        auto key_slice{to_slice(key)};
        CHECK(code_cursor.erase(key_slice));
        auto code_stats{rw_txn.get_map_stat(code_map)};
        REQUIRE(code_stats.ms_entries == 0);
        REQUIRE(code_stats.ms_depth == 0);
        REQUIRE(code_stats.ms_branch_pages == 0);
        REQUIRE(code_stats.ms_leaf_pages == 0);
        REQUIRE(code_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages if we erase
    }

    SECTION("erase + upsert same value w/ 2 commits causes two free pages") {
        {
            auto rw_txn{env.start_write()};
            auto code_map{open_map(rw_txn, table::kCode)};
            auto code_cursor{rw_txn.open_cursor(code_map)};
            auto key_slice{to_slice(key)};
            CHECK(code_cursor.erase(key_slice));
            auto code_stats{rw_txn.get_map_stat(code_map)};
            REQUIRE(code_stats.ms_entries == 0);
            REQUIRE(code_stats.ms_depth == 0);
            REQUIRE(code_stats.ms_branch_pages == 0);
            REQUIRE(code_stats.ms_leaf_pages == 0);
            REQUIRE(code_stats.ms_overflow_pages == 0);
            rw_txn.commit();
            CHECK(get_free_pages(env) == 2);
        }
        {
            auto rw_txn{env.start_write()};
            auto code_map{open_map(rw_txn, table::kCode)};
            auto code_cursor{rw_txn.open_cursor(code_map)};
            auto key_slice{to_slice(key)};
            Bytes value(max_value_size_for_leaf_page(rw_txn, key.size()), static_cast<uint8_t>(10));
            auto value_slice{to_slice(value)};
            code_cursor.upsert(key_slice, value_slice);
            auto code_stats{rw_txn.get_map_stat(code_map)};
            REQUIRE(code_stats.ms_entries == 1);
            REQUIRE(code_stats.ms_depth == 1);
            REQUIRE(code_stats.ms_branch_pages == 0);
            REQUIRE(code_stats.ms_leaf_pages == 1);
            REQUIRE(code_stats.ms_overflow_pages == 0);
            rw_txn.commit();
            CHECK(get_free_pages(env) == 2);
        }
    }
}

TEST_CASE("Multi-value erase+upsert w/ same value increases free pages") {
    TemporaryDirectory tmp_dir{};
    auto data_directory{std::make_unique<DataDirectory>(tmp_dir.path(), /*create=*/true)};
    EnvConfig env_config{
        .path = data_directory->chaindata().path().string(),
        .create = true,
        .readonly = false,
        .exclusive = false,
        .in_memory = true,
    };
    auto env{open_env(env_config)};

    // We need to split max multi-value data size between key and value
    constexpr size_t kKeySize{20};  // just to copycat account address size
    auto ro_txn{env.start_read()};
    auto stat = env.get_stat(ro_txn);
    auto max_non_initial_value_size = max_multivalue_size_for_leaf_page(ro_txn);
    ro_txn.abort();
    const size_t max_first_value_size{max_non_initial_value_size - kKeySize};  // we need to take key size into account once
    const Bytes key(kKeySize, '\0');

    // Initialize the map content w/ one max-size value [scope needed to limit rw_txn lifecycle]
    {
        auto rw_txn{env.start_write()};
        auto plain_state_map{open_map(rw_txn, table::kPlainState)};
        auto plain_state_stats{rw_txn.get_map_stat(plain_state_map)};
        REQUIRE(plain_state_stats.ms_entries == 0);
        REQUIRE(plain_state_stats.ms_depth == 0);
        REQUIRE(plain_state_stats.ms_branch_pages == 0);
        REQUIRE(plain_state_stats.ms_leaf_pages == 0);
        REQUIRE(plain_state_stats.ms_overflow_pages == 0);
        auto plain_state_cursor{rw_txn.open_cursor(plain_state_map)};
        Bytes value(max_first_value_size, static_cast<uint8_t>(10));
        plain_state_cursor.insert(to_slice(key), to_slice(value));  // insert or upsert equivalent here
        plain_state_stats = rw_txn.get_map_stat(plain_state_map);
        REQUIRE(plain_state_stats.ms_entries == 1);  // we have 1 value here
        REQUIRE(plain_state_stats.ms_depth == 1);
        REQUIRE(plain_state_stats.ms_branch_pages == 0);
        REQUIRE(plain_state_stats.ms_leaf_pages == 1);
        REQUIRE(plain_state_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 0);  // No free pages after
    }

    SECTION("upsert same value does not cause any free page") {
        auto rw_txn{env.start_write()};
        auto plain_state_map{open_map(rw_txn, table::kPlainState)};
        auto plain_state_cursor{rw_txn.open_cursor(plain_state_map)};
        auto key_slice{to_slice(key)};
        Bytes value(max_first_value_size, static_cast<uint8_t>(10));
        auto value_slice{to_slice(value)};
        plain_state_cursor.upsert(key_slice, value_slice);
        auto plain_state_stats{rw_txn.get_map_stat(plain_state_map)};
        REQUIRE(plain_state_stats.ms_entries == 1);
        REQUIRE(plain_state_stats.ms_depth == 1);
        REQUIRE(plain_state_stats.ms_branch_pages == 0);
        REQUIRE(plain_state_stats.ms_leaf_pages == 1);
        REQUIRE(plain_state_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 0);  // no free page produced
    }

    SECTION("erase + upsert same value causes two free pages") {
        auto rw_txn{env.start_write()};
        auto plain_state_map{open_map(rw_txn, table::kPlainState)};
        auto plain_state_cursor{rw_txn.open_cursor(plain_state_map)};
        auto key_slice{to_slice(key)};
        CHECK(plain_state_cursor.erase(key_slice, /*whole_multivalue=*/true));
        Bytes value(max_first_value_size, static_cast<uint8_t>(10));
        auto value_slice{to_slice(value)};
        plain_state_cursor.upsert(key_slice, value_slice);
        auto plain_state_stats{rw_txn.get_map_stat(plain_state_map)};
        REQUIRE(plain_state_stats.ms_entries == 1);
        REQUIRE(plain_state_stats.ms_depth == 1);
        REQUIRE(plain_state_stats.ms_branch_pages == 0);
        REQUIRE(plain_state_stats.ms_leaf_pages == 1);
        REQUIRE(plain_state_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages if we erase+upsert w/ same value => bad pattern
    }

    SECTION("upsert different value causes two free pages") {
        auto rw_txn{env.start_write()};
        auto plain_state_map{open_map(rw_txn, table::kPlainState)};
        auto plain_state_cursor{rw_txn.open_cursor(plain_state_map)};
        auto key_slice{to_slice(key)};
        Bytes value(max_non_initial_value_size, static_cast<uint8_t>(11));
        auto value_slice{to_slice(value)};
        plain_state_cursor.upsert(key_slice, value_slice);
        auto plain_state_stats{rw_txn.get_map_stat(plain_state_map)};
        REQUIRE(plain_state_stats.ms_entries == 2);  // we have 2 values here since table is multi-value
        REQUIRE(plain_state_stats.ms_depth == 1);
        REQUIRE(plain_state_stats.ms_branch_pages == 0);
        REQUIRE(plain_state_stats.ms_leaf_pages == 2);  // we have 2 max data values hence we need 2 pages
        REQUIRE(plain_state_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages in any case
    }

    SECTION("erase + upsert different value causes two free pages") {
        auto rw_txn{env.start_write()};
        auto plain_state_map{open_map(rw_txn, table::kPlainState)};
        auto plain_state_cursor{rw_txn.open_cursor(plain_state_map)};
        auto key_slice{to_slice(key)};
        CHECK(plain_state_cursor.erase(key_slice, /*whole_multivalue=*/true));
        Bytes value(max_first_value_size, static_cast<uint8_t>(11));
        auto value_slice{to_slice(value)};
        plain_state_cursor.upsert(key_slice, value_slice);
        auto plain_state_stats{rw_txn.get_map_stat(plain_state_map)};
        REQUIRE(plain_state_stats.ms_entries == 1);
        REQUIRE(plain_state_stats.ms_depth == 1);
        REQUIRE(plain_state_stats.ms_branch_pages == 0);
        REQUIRE(plain_state_stats.ms_leaf_pages == 1);
        REQUIRE(plain_state_stats.ms_overflow_pages == 0);
        rw_txn.commit();
        CHECK(get_free_pages(env) == 2);  // +2 free pages in any case
    }
}

}  // namespace silkworm::datastore::kvdb
