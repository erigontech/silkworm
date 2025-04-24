// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "split_cursor.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/types/address.hpp>
#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>

namespace silkworm::rpc::ethdb {

using evmc::literals::operator""_bytes32;
using evmc::literals::operator""_address;
using testing::_;
using testing::InvokeWithoutArgs;

static const silkworm::Bytes kValue{*silkworm::from_hex("0x000000000000000000000000000000000000000000000000000000000000001134567")};
static const silkworm::Bytes kEmptyKey{};
static const silkworm::Bytes kShortKey{*silkworm::from_hex("0x79a4d35bd00b1843ec5292217e71dace5e5")};
static const silkworm::Bytes kWrongKeyLastByte{*silkworm::from_hex("0x79a4d35bd00b1843ec5292217e71dace5e5a7430")};
static const silkworm::Bytes kWrongKeyFirstByte{*silkworm::from_hex("0x59a4d35bd00b1843ec5292217e71dace5e5a7430")};
static const silkworm::Bytes kKey{(0x79a4d35bd00b1843ec5292217e71dace5e5a7439_address).bytes, kAddressLength};
static const silkworm::Bytes kCorrectKey{*silkworm::from_hex("0x79a4d35bd00b1843ec5292217e71dace5e5a7439")};
static const silkworm::Bytes kLocation{(0x0000000000000000000000000000000000000000000000000000000000000001_bytes32).bytes, kHashLength};

TEST_CASE("split cursor dup sort") {
    WorkerPool pool{1};
    db::test_util::MockCursorDupSort csdp;

    SECTION("0 matching bits: seek_both, key not exists") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 0, silkworm::kAddressLength, 0);

        EXPECT_CALL(csdp, seek_both(_, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
                co_return silkworm::Bytes{};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek_both(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(kKey));
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: seek_both, key not exists") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, seek_both(_, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
                co_return silkworm::Bytes{};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek_both(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address odd matching bits: seek_both, key not exists") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 153, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, seek_both(_, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
                co_return silkworm::Bytes{};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek_both(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: seek_both, key exists") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, seek_both(_, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
                co_return kValue;
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek_both(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(kKey));
        CHECK(silkworm::to_hex(skv.key2) == silkworm::to_hex(kLocation));
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value) == "134567");
    }

    SECTION("evmc:.address maching bits: next_dup, key exists short key") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kShortKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: next_dup, key exists empty key") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kEmptyKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: next_dup, key exists wrong key last byte") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kWrongKeyLastByte, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: next_dup, key exists wrong key first byte") {
        SplitCursorDupSort sc(csdp, kKey, kLocation, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kWrongKeyFirstByte, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }
}

TEST_CASE("split cursor") {
    WorkerPool pool{1};
    db::test_util::MockCursor csdp;

    SECTION("0 matching bits: seek, key not exists") {
        SplitCursor sc(csdp, kKey, 0, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kCorrectKey, {}};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(kKey));
        CHECK(silkworm::to_hex(skv.key2) == silkworm::to_hex(kKey));
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: seek, key not exists") {
        SplitCursor sc(csdp, kKey, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kShortKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address odd matching bits: seek, key not exists") {
        SplitCursor sc(csdp, kKey, 131, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kShortKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: seek, key exists") {
        SplitCursor sc(csdp, kKey, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kCorrectKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(kKey));
        CHECK(silkworm::to_hex(skv.key2) == silkworm::to_hex(kKey));
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value) == "0000000000000000000000000000000000000000000000000000000000000001134567");
    }

    SECTION("evmc:.address matching bits: next_dup, key exists short key") {
        SplitCursor sc(csdp, kKey, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kShortKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: next, empty key") {
        SplitCursor sc(csdp, kKey, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kEmptyKey, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: next, key exists wrong key last byte") {
        SplitCursor sc(csdp, kKey, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);
        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kWrongKeyLastByte, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address matching bits: next, key exists wrong key first byte") {
        SplitCursor sc(csdp, kKey, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{kWrongKeyFirstByte, kValue};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }
}

}  // namespace silkworm::rpc::ethdb
