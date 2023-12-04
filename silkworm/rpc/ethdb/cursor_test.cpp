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

#include "cursor.hpp"

#include <string>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/thread_pool.hpp>
#include <boost/asio/use_future.hpp>
#include <catch2/catch.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/types/address.hpp>
#include <silkworm/rpc/test/mock_cursor.hpp>

namespace silkworm::rpc::ethdb {

using Catch::Matchers::Message;
using evmc::literals::operator""_bytes32;
using evmc::literals::operator""_address;
using testing::_;
using testing::InvokeWithoutArgs;

static const silkworm::Bytes value{*silkworm::from_hex("0x000000000000000000000000000000000000000000000000000000000000001134567")};
static const silkworm::Bytes empty_key{};
static const silkworm::Bytes short_key{*silkworm::from_hex("0x79a4d35bd00b1843ec5292217e71dace5e5")};
static const silkworm::Bytes wrong_key_last_byte{*silkworm::from_hex("0x79a4d35bd00b1843ec5292217e71dace5e5a7430")};
static const silkworm::Bytes wrong_key_first_byte{*silkworm::from_hex("0x59a4d35bd00b1843ec5292217e71dace5e5a7430")};
static const silkworm::Bytes key{(0x79a4d35bd00b1843ec5292217e71dace5e5a7439_address).bytes, kAddressLength};
static const silkworm::Bytes correct_key{*silkworm::from_hex("0x79a4d35bd00b1843ec5292217e71dace5e5a7439")};
static const silkworm::Bytes location{(0x0000000000000000000000000000000000000000000000000000000000000001_bytes32).bytes, kHashLength};

TEST_CASE("split cursor dup sort") {
    boost::asio::thread_pool pool{1};
    test::MockCursorDupSort csdp;

    SECTION("0 maching bits: seek_both, key not exists") {
        SplitCursorDupSort sc(csdp, key, location, 0, silkworm::kAddressLength, 0);

        EXPECT_CALL(csdp, seek_both(_, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
                co_return silkworm::Bytes{};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek_both(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(key));
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: seek_both, key not exists") {
        SplitCursorDupSort sc(csdp, key, location, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
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

    SECTION("evmc:.address odd maching bits: seek_both, key not exists") {
        SplitCursorDupSort sc(csdp, key, location, 153, silkworm::kAddressLength,
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

    SECTION("evmc:.address maching bits: seek_both, key exists") {
        SplitCursorDupSort sc(csdp, key, location, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, seek_both(_, _))
            .WillOnce(InvokeWithoutArgs([]() -> Task<silkworm::Bytes> {
                co_return value;
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek_both(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(key));
        CHECK(silkworm::to_hex(skv.key2) == silkworm::to_hex(location));
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value) == "134567");
    }

    SECTION("evmc:.address maching bits: next_dup, key exists short key") {
        SplitCursorDupSort sc(csdp, key, location, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{short_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: next_dup, key exists empty key") {
        SplitCursorDupSort sc(csdp, key, location, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{empty_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: next_dup, key exists wrong key last byte") {
        SplitCursorDupSort sc(csdp, key, location, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{wrong_key_last_byte, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next_dup(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: next_dup, key exists wrong key first byte") {
        SplitCursorDupSort sc(csdp, key, location, 8 * silkworm::kAddressLength, silkworm::kAddressLength,
                              silkworm::kHashLength);

        EXPECT_CALL(csdp, next_dup())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{wrong_key_first_byte, value};
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
    boost::asio::thread_pool pool{1};
    test::MockCursor csdp;

    SECTION("0 maching bits: seek, key not exists") {
        SplitCursor sc(csdp, key, 0, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{correct_key, {}};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(key));
        CHECK(silkworm::to_hex(skv.key2) == silkworm::to_hex(key));
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: seek, key not exists") {
        SplitCursor sc(csdp, key, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{short_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address odd maching bits: seek, key not exists") {
        SplitCursor sc(csdp, key, 131, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{short_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: seek, key exists") {
        SplitCursor sc(csdp, key, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, seek(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{correct_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.seek(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1) == silkworm::to_hex(key));
        CHECK(silkworm::to_hex(skv.key2) == silkworm::to_hex(key));
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value) == "0000000000000000000000000000000000000000000000000000000000000001134567");
    }

    SECTION("evmc:.address maching bits: next_dup, key exists short key") {
        SplitCursor sc(csdp, key, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{short_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: next, empty key") {
        SplitCursor sc(csdp, key, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{empty_key, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: next, key exists wrong key last byte") {
        SplitCursor sc(csdp, key, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);
        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{wrong_key_last_byte, value};
            }));
        auto result = boost::asio::co_spawn(pool, sc.next(), boost::asio::use_future);
        const SplittedKeyValue& skv = result.get();

        CHECK(silkworm::to_hex(skv.key1).empty());
        CHECK(silkworm::to_hex(skv.key2).empty());
        CHECK(silkworm::to_hex(skv.key3).empty());
        CHECK(silkworm::to_hex(skv.value).empty());
    }

    SECTION("evmc:.address maching bits: next, key exists wrong key first byte") {
        SplitCursor sc(csdp, key, 8 * silkworm::kAddressLength, silkworm::kAddressLength, 0, silkworm::kAddressLength);

        EXPECT_CALL(csdp, next())
            .WillOnce(InvokeWithoutArgs([]() -> Task<KeyValue> {
                co_return KeyValue{wrong_key_first_byte, value};
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
