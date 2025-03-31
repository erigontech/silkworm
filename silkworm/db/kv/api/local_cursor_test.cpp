// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "local_cursor.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <catch2/catch_test_macros.hpp>

#include <silkworm/db/test_util/test_database_context.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/infra/test_util/fixture.hpp>

#include "../../tables.hpp"

namespace silkworm::db::kv::api {

using namespace silkworm::test_util;
using datastore::kvdb::ROTxnManaged;
using silkworm::test_util::ContextTestBase;
using test_util::TestDatabaseContext;

struct LocalCursorTest : public ContextTestBase {
    TemporaryDirectory tmp_dir;
    TestDatabaseContext database{tmp_dir};
    static inline uint32_t last_cursor_id{0};

    datastore::kvdb::ROAccess chaindata() const { return database.chaindata(); }
};

// In all following tests we need to create the MDBX transaction using the io_context scheduler thread, so we simply
// wrap the test body into a coroutine lamda run onto the scheduler facility provided by ContextTestBase.

TEST_CASE_METHOD(LocalCursorTest, "LocalCursor::open_cursor", "[db][kv][api][local_cursor]") {
    spawn_and_wait([&]() -> Task<void> {
        ROTxnManaged txn = chaindata().start_ro_tx();
        LocalCursor cursor{txn, ++last_cursor_id};

        CHECK_NOTHROW(co_await cursor.open_cursor(table::kHeadersName, /*is_dup_sorted=*/false));
        CHECK(cursor.cursor_id() > 0);
    });
}

TEST_CASE_METHOD(LocalCursorTest, "LocalCursor::close_cursor", "[db][kv][api][local_cursor]") {
    spawn_and_wait([&]() -> Task<void> {
        ROTxnManaged txn = chaindata().start_ro_tx();
        LocalCursor cursor{txn, ++last_cursor_id};
        REQUIRE_NOTHROW(co_await cursor.open_cursor(table::kHeadersName, /*is_dup_sorted=*/false));
        REQUIRE(cursor.cursor_id() > 0);

        CHECK_NOTHROW(co_await cursor.close_cursor());
        CHECK(cursor.cursor_id() == 0);
    });
}

static auto decode_header(ByteView data_view) {
    BlockHeader header;
    return rlp::decode(data_view, header);
}

TEST_CASE_METHOD(LocalCursorTest, "LocalCursor::first", "[db][kv][api][local_cursor]") {
    spawn_and_wait([&]() -> Task<void> {
        ROTxnManaged txn = chaindata().start_ro_tx();
        LocalCursor cursor{txn, ++last_cursor_id};
        REQUIRE_NOTHROW(co_await cursor.open_cursor(table::kHeadersName, /*is_dup_sorted=*/false));

        KeyValue k_and_v{};
        CHECK_NOTHROW((k_and_v = co_await cursor.first()));
        CHECK(k_and_v.key == block_key(0, Hash{0x51181a9927eef038d77a7be22d9555af451cfba4bf4fd02e43ea592c1687eb98_bytes32}.bytes));
        CHECK(decode_header(k_and_v.value));

        REQUIRE_NOTHROW(co_await cursor.close_cursor());
    });
}

TEST_CASE_METHOD(LocalCursorTest, "LocalCursor::last", "[db][kv][api][local_cursor]") {
    spawn_and_wait([&]() -> Task<void> {
        ROTxnManaged txn = chaindata().start_ro_tx();
        LocalCursor cursor{txn, ++last_cursor_id};
        REQUIRE_NOTHROW(co_await cursor.open_cursor(table::kHeadersName, /*is_dup_sorted=*/false));

        KeyValue k_and_v{};
        CHECK_NOTHROW((k_and_v = co_await cursor.last()));
        CHECK(k_and_v.key == block_key(9, Hash{0x9032fd0afc97b3c5b28fe887051ecb2cc3a3475c102b0aeeaadaebd87d8e1cd3_bytes32}.bytes));
        CHECK(decode_header(k_and_v.value));

        REQUIRE_NOTHROW(co_await cursor.close_cursor());
    });
}

TEST_CASE_METHOD(LocalCursorTest, "LocalCursor::next", "[db][kv][api][local_cursor]") {
    spawn_and_wait([&]() -> Task<void> {
        ROTxnManaged txn = chaindata().start_ro_tx();
        LocalCursor cursor{txn, ++last_cursor_id};
        REQUIRE_NOTHROW(co_await cursor.open_cursor(table::kHeadersName, /*is_dup_sorted=*/false));

        KeyValue k_and_v{};
        CHECK_NOTHROW((k_and_v = co_await cursor.next()));
        CHECK(k_and_v.key == block_key(0, Hash{0x51181a9927eef038d77a7be22d9555af451cfba4bf4fd02e43ea592c1687eb98_bytes32}.bytes));
        CHECK(decode_header(k_and_v.value));
        CHECK_NOTHROW((k_and_v = co_await cursor.next()));
        CHECK(k_and_v.key == block_key(1, Hash{0x7cb4dd3daba1f739d0c1ec7d998b4a2f6fd83019116455afa54ca4f49dfa0ad4_bytes32}.bytes));
        CHECK(decode_header(k_and_v.value));

        REQUIRE_NOTHROW(co_await cursor.close_cursor());
    });
}

TEST_CASE_METHOD(LocalCursorTest, "LocalCursor::previous", "[db][kv][api][local_cursor]") {
    spawn_and_wait([&]() -> Task<void> {
        ROTxnManaged txn = chaindata().start_ro_tx();
        LocalCursor cursor{txn, ++last_cursor_id};
        REQUIRE_NOTHROW(co_await cursor.open_cursor(table::kHeadersName, /*is_dup_sorted=*/false));

        KeyValue k_and_v{};
        CHECK_NOTHROW((k_and_v = co_await cursor.last()));
        CHECK_NOTHROW((k_and_v = co_await cursor.previous()));
        CHECK(k_and_v.key == block_key(8, Hash{0x3d50efbbad1818ab34b8d2fd272aa0d149225e7c489b9f955b7758ad7c5918df_bytes32}.bytes));
        CHECK(decode_header(k_and_v.value));
        CHECK_NOTHROW((k_and_v = co_await cursor.previous()));
        CHECK(k_and_v.key == block_key(7, Hash{0xa5c7bcf72090b64c6f00fae9897096b7f1593358d4915dc30b4e60f13ce6e301_bytes32}.bytes));
        CHECK(decode_header(k_and_v.value));

        REQUIRE_NOTHROW(co_await cursor.close_cursor());
    });
}

}  // namespace silkworm::db::kv::api
