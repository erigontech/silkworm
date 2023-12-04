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

#include "cached_database.hpp"

#include <memory>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/util.hpp>
#include <silkworm/node/db/tables.hpp>
#include <silkworm/rpc/core/rawdb/accessors.hpp>
#include <silkworm/rpc/ethdb/kv/state_cache.hpp>
#include <silkworm/rpc/test/dummy_transaction.hpp>
#include <silkworm/rpc/test/mock_cursor.hpp>
#include <silkworm/rpc/test/mock_state_cache.hpp>
#include <silkworm/rpc/test/mock_transaction.hpp>
#include <silkworm/rpc/types/block.hpp>

namespace silkworm::rpc::ethdb::kv {

using testing::_;
using testing::InvokeWithoutArgs;
using testing::Return;

static constexpr auto kTestBlockNumber{1'000'000};

static const auto kTestData{*silkworm::from_hex("600035600055")};
static const silkworm::Bytes kZeroBytes{};
static silkworm::Bytes key1{*silkworm::from_hex("68656164426c6f636b48617368")};
static silkworm::Bytes key2{*silkworm::from_hex("457865637574696f6e")};

TEST_CASE("CachedDatabase::CachedDatabase", "[rpc][ethdb][kv][cached_database]") {
    BlockNumberOrHash block_id{0};
    test::MockTransaction mock_txn;
    test::MockStateCache mock_cache;
    CHECK_NOTHROW(CachedDatabase{block_id, mock_txn, mock_cache});
}

TEST_CASE("CachedDatabase::get_one", "[rpc][ethdb][kv][cached_database]") {
    boost::asio::thread_pool pool{1};
    std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
    test::MockStateCache mock_cache;

    SECTION("cache miss: request unexpected table in latest block") {
        BlockNumberOrHash block_id{kTestBlockNumber};
        test::DummyTransaction fake_txn{0, mock_cursor};
        CachedDatabase cached_db{block_id, fake_txn, mock_cache};
        // Mock cursor shall provide the value returned by get
        EXPECT_CALL(*mock_cursor, seek_exact(_)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
            co_return KeyValue{kZeroBytes, kZeroBytes};
        }));
        const std::string table = db::table::kHeadersName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
        auto result = boost::asio::co_spawn(pool, cached_db.get_one(table, kZeroBytes), boost::asio::use_future);
        const auto value = result.get();
        CHECK(value == kZeroBytes);
    }

    SECTION("cache hit: empty key from PlainState in latest block return nullopt") {
        BlockNumberOrHash block_id{kTestBlockNumber};
        test::DummyTransaction fake_txn{0, mock_cursor};
        auto* mock_view = new test::MockStateView;
        CachedDatabase cached_db{block_id, fake_txn, mock_cache};
        // Mock cache shall return the mock view instance
        EXPECT_CALL(mock_cache, get_view(_)).WillOnce(InvokeWithoutArgs([=]() -> std::unique_ptr<StateView> {
            return std::unique_ptr<test::MockStateView>{mock_view};
        }));
        // Mock view shall be used to read value from data cache
        EXPECT_CALL(*mock_view, get(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<silkworm::Bytes>> {
            co_return std::nullopt;
        }));
        const std::string table = db::table::kPlainStateName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
        auto result = boost::asio::co_spawn(pool, cached_db.get_one(table, kZeroBytes), boost::asio::use_future);
        const auto value = result.get();
        CHECK(value == kZeroBytes);
    }

    SECTION("cache hit: empty key from PlainState in latest block") {
        BlockNumberOrHash block_id{kTestBlockNumber};
        test::DummyTransaction fake_txn{0, mock_cursor};
        auto* mock_view = new test::MockStateView;
        CachedDatabase cached_db{block_id, fake_txn, mock_cache};
        // Mock cache shall return the mock view instance
        EXPECT_CALL(mock_cache, get_view(_)).WillOnce(InvokeWithoutArgs([=]() -> std::unique_ptr<StateView> {
            return std::unique_ptr<test::MockStateView>{mock_view};
        }));
        // Mock view shall be used to read value from data cache
        EXPECT_CALL(*mock_view, get(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<silkworm::Bytes>> {
            co_return kTestData;
        }));
        const std::string table = db::table::kPlainStateName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
        auto result = boost::asio::co_spawn(pool, cached_db.get_one(table, kZeroBytes), boost::asio::use_future);
        const auto value = result.get();
        CHECK(value == kTestData);
    }

    SECTION("cache hit: empty key from Code in latest block") {
        BlockNumberOrHash block_id{kTestBlockNumber};
        test::DummyTransaction fake_txn{0, mock_cursor};
        auto* mock_view = new test::MockStateView;
        CachedDatabase cached_db{block_id, fake_txn, mock_cache};
        // Mock cache shall return the mock view instance
        EXPECT_CALL(mock_cache, get_view(_)).WillOnce(InvokeWithoutArgs([=]() -> std::unique_ptr<StateView> {
            return std::unique_ptr<test::MockStateView>{mock_view};
        }));
        // Mock view shall be used to read value from code cache
        EXPECT_CALL(*mock_view, get_code(_)).WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<silkworm::Bytes>> {
            co_return kTestData;
        }));
        const std::string table = db::table::kCodeName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
        auto result = boost::asio::co_spawn(pool, cached_db.get_one(table, kZeroBytes), boost::asio::use_future);
        const auto value = result.get();
        CHECK(value == kTestData);
    }
}

TEST_CASE("CachedDatabase::get", "[rpc][ethdb][kv][cached_database]") {
    boost::asio::thread_pool pool{1};
    std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
    test::DummyTransaction fake_txn{0, mock_cursor};
    test::MockStateCache mock_cache;
    BlockNumberOrHash block_id{kTestBlockNumber};
    CachedDatabase cached_db{block_id, fake_txn, mock_cache};
    // Mock cursor shall provide the value returned by get
    EXPECT_CALL(*mock_cursor, seek(_)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{kZeroBytes, kZeroBytes};
    }));
    const std::string table = db::table::kPlainStateName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
    auto result = boost::asio::co_spawn(pool, cached_db.get(table, kZeroBytes), boost::asio::use_future);
    const auto kv = result.get();
    CHECK(kv.value.empty());
}

TEST_CASE("CachedDatabase::get_both_range", "[rpc][ethdb][kv][cached_database]") {
    boost::asio::thread_pool pool{1};
    std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
    test::DummyTransaction fake_txn{0, mock_cursor};
    test::MockStateCache mock_cache;
    BlockNumberOrHash block_id{kTestBlockNumber};
    CachedDatabase cached_db{block_id, fake_txn, mock_cache};
    // Mock cursor shall provide the value returned by get_both_range
    EXPECT_CALL(*mock_cursor, seek_both(_, _)).WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
        co_return kZeroBytes;
    }));
    const std::string table = db::table::kCodeName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
    auto result = boost::asio::co_spawn(pool, cached_db.get_both_range(table, kZeroBytes, kZeroBytes), boost::asio::use_future);
    const auto value = result.get();
    CHECK(value);
    if (value) {
        CHECK((*value).empty());
    }
}

TEST_CASE("CachedDatabase::walk", "[rpc][ethdb][kv][cached_database]") {
    boost::asio::thread_pool pool{1};
    std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
    test::DummyTransaction fake_txn{0, mock_cursor};
    test::MockStateCache mock_cache;
    BlockNumberOrHash block_id{kTestBlockNumber};
    CachedDatabase cached_db{block_id, fake_txn, mock_cache};
    // Mock cursor shall provide the starting key-value pair for the walk
    EXPECT_CALL(*mock_cursor, seek(_)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{*silkworm::from_hex("00"), kZeroBytes};
    }));
    core::rawdb::Walker walker = [&](const silkworm::Bytes& /*k*/, const silkworm::Bytes& /*v*/) -> bool {
        return false;
    };
    const std::string table = db::table::kCodeName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
    auto result = boost::asio::co_spawn(pool, cached_db.walk(table, kZeroBytes, 0, walker), boost::asio::use_future);
    CHECK_NOTHROW(result.get());
}

TEST_CASE("CachedDatabase::for_prefix", "[rpc][ethdb][kv][cached_database]") {
    boost::asio::thread_pool pool{1};
    std::shared_ptr<test::MockCursorDupSort> mock_cursor = std::make_shared<test::MockCursorDupSort>();
    test::DummyTransaction fake_txn{0, mock_cursor};
    test::MockStateCache mock_cache;
    BlockNumberOrHash block_id{kTestBlockNumber};
    CachedDatabase cached_db{block_id, fake_txn, mock_cache};
    // Mock cursor shall provide the starting key-value pair for the iteration
    EXPECT_CALL(*mock_cursor, seek(_)).WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
        co_return KeyValue{*silkworm::from_hex("00"), kZeroBytes};
    }));
    core::rawdb::Walker walker = [&](const silkworm::Bytes& /*k*/, const silkworm::Bytes& /*v*/) -> bool {
        return false;
    };
    const std::string table = db::table::kCodeName;  // Needed to extend the table name lifetime until boost::asio::co_spawn is done
    auto result = boost::asio::co_spawn(pool, cached_db.for_prefix(table, kZeroBytes, walker), boost::asio::use_future);
    CHECK_NOTHROW(result.get());
}

}  // namespace silkworm::rpc::ethdb::kv
