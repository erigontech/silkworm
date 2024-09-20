/*
   Copyright 2024 The Silkworm Authors

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

#include "txn_num.hpp"

#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/db/test_util/mock_cursor.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/infra/test_util/fixture.hpp>

#include "../tables.hpp"

namespace silkworm::db::txn {

using silkworm::test_util::ContextTestBase;
using silkworm::test_util::Fixtures;
using test_util::MockCursor;
using test_util::MockTransaction;
using testing::_;
using testing::Invoke;
using testing::Unused;

struct TxNumText : ContextTestBase {
    MockTransaction transaction;
};

TEST_CASE_METHOD(TxNumText, "max_tx_num", "[db][txn][tx_num]") {
    auto cursor = std::make_shared<MockCursor>();
    EXPECT_CALL(transaction, cursor(table::kMaxTxNumName)).WillOnce(Invoke([&cursor](Unused) -> Task<std::shared_ptr<kv::api::Cursor>> {
        co_return cursor;
    }));
    struct BlockNumAndKeyValue {
        BlockNum block_number;
        kv::api::KeyValue key_value;
    };
    const Fixtures<BlockNumAndKeyValue, TxNum> fixtures{
        {{0, {*from_hex("0000000000000000"), *from_hex("000000000000000A")}}, 10},
        {{1, {*from_hex("0000000000000001"), *from_hex("000000000000000F")}}, 15},
    };
    for (const auto& [block_num_and_kv, expected_max_tx_num] : fixtures) {
        const auto [block_number, key_value] = block_num_and_kv;
        SECTION("block_number: " + std::to_string(block_number)) {
            EXPECT_CALL(*cursor, seek_exact(_)).WillOnce(Invoke([=](Unused) -> Task<kv::api::KeyValue> {
                co_return key_value;
            }));
            CHECK(spawn_and_wait(max_tx_num(transaction, block_number)) == expected_max_tx_num);
        }
    }
}

TEST_CASE_METHOD(TxNumText, "min_tx_num", "[db][txn][tx_num]") {
    auto cursor = std::make_shared<MockCursor>();
    struct BlockNumAndKeyValue {
        BlockNum block_number;
        kv::api::KeyValue key_value;
    };
    const Fixtures<BlockNumAndKeyValue, TxNum> fixtures{
        {{0, {*from_hex("0000000000000000"), *from_hex("0000000000000000")}}, 0},
        {{1, {*from_hex("0000000000000000"), *from_hex("000000000000000E")}}, 15},
    };
    for (const auto& [block_num_and_kv, expected_max_tx_num] : fixtures) {
        const auto [block_number, key_value] = block_num_and_kv;
        SECTION("block_number: " + std::to_string(block_number)) {
            if (block_number != 0) {
                EXPECT_CALL(transaction, cursor(table::kMaxTxNumName)).WillOnce(Invoke([&cursor](Unused) -> Task<std::shared_ptr<kv::api::Cursor>> {
                    co_return cursor;
                }));
                EXPECT_CALL(*cursor, seek_exact(_)).WillOnce(Invoke([=](Unused) -> Task<kv::api::KeyValue> {
                    co_return key_value;
                }));
            }
            CHECK(spawn_and_wait(min_tx_num(transaction, block_number)) == expected_max_tx_num);
        }
    }
}

TEST_CASE_METHOD(TxNumText, "first_tx_num", "[db][txn][tx_num]") {
    auto cursor = std::make_shared<MockCursor>();
    const Fixtures<kv::api::KeyValue, std::optional<BlockNumAndTxnNumber>> fixtures{
        {{*from_hex(""), *from_hex("")}, BlockNumAndTxnNumber{}},
        {{*from_hex("0000000000000000"), *from_hex("0000000000000001")}, BlockNumAndTxnNumber{0, 1}},
        {{*from_hex("0000000000000001"), *from_hex("000000000000000E")}, BlockNumAndTxnNumber{1, 14}},
        {{*from_hex("00000000000000"), *from_hex("000000000000000E")}, std::nullopt},  // wrong key format
        {{*from_hex("0000000000000001"), *from_hex("00")}, std::nullopt},              // wrong value format
    };
    for (size_t i{0}; i < fixtures.size(); ++i) {
        const auto& [key_value, expected_block_and_txn_num] = fixtures[i];
        SECTION("sequence: " + std::to_string(i)) {
            EXPECT_CALL(transaction, cursor(table::kMaxTxNumName)).WillOnce(Invoke([&cursor](Unused) -> Task<std::shared_ptr<kv::api::Cursor>> {
                co_return cursor;
            }));
            EXPECT_CALL(*cursor, first()).WillOnce(Invoke([=]() -> Task<kv::api::KeyValue> {
                co_return key_value;
            }));
            if (expected_block_and_txn_num) {
                CHECK(spawn_and_wait(first_tx_num(transaction)) == *expected_block_and_txn_num);
            } else {
                CHECK_THROWS_AS(spawn_and_wait(first_tx_num(transaction)), std::length_error);
            }
        }
    }
}

TEST_CASE_METHOD(TxNumText, "last_tx_num", "[db][txn][tx_num]") {
    auto cursor = std::make_shared<MockCursor>();
    const Fixtures<kv::api::KeyValue, std::optional<BlockNumAndTxnNumber>> fixtures{
        {{*from_hex(""), *from_hex("")}, BlockNumAndTxnNumber{}},
        {{*from_hex("0000000000000000"), *from_hex("0000000000000001")}, BlockNumAndTxnNumber{0, 1}},
        {{*from_hex("0000000000000001"), *from_hex("000000000000000E")}, BlockNumAndTxnNumber{1, 14}},
        {{*from_hex("00000000000000"), *from_hex("000000000000000E")}, std::nullopt},  // wrong key format
        {{*from_hex("0000000000000001"), *from_hex("00")}, std::nullopt},              // wrong value format
    };
    for (size_t i{0}; i < fixtures.size(); ++i) {
        const auto& [key_value, expected_block_and_txn_num] = fixtures[i];
        SECTION("sequence: " + std::to_string(i)) {
            EXPECT_CALL(transaction, cursor(table::kMaxTxNumName)).WillOnce(Invoke([&cursor](Unused) -> Task<std::shared_ptr<kv::api::Cursor>> {
                co_return cursor;
            }));
            EXPECT_CALL(*cursor, last()).WillOnce(Invoke([=]() -> Task<kv::api::KeyValue> {
                co_return key_value;
            }));
            if (expected_block_and_txn_num) {
                CHECK(spawn_and_wait(last_tx_num(transaction)) == *expected_block_and_txn_num);
            } else {
                CHECK_THROWS_AS(spawn_and_wait(last_tx_num(transaction)), std::length_error);
            }
        }
    }
}

}  // namespace silkworm::db::txn
