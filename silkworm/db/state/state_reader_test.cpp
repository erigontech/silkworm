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

#include "state_reader.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/base.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/test_util/context_test_base.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::db::state {

using testing::_;
using testing::Invoke;
using testing::Unused;

#ifndef SILKWORM_SANITIZE
static const evmc::address kZeroAddress{};
static const Bytes kEncodedAccount{*from_hex(
    "01020203e820f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92390105")};

static const evmc::bytes32 kLocationHash{};
static const Bytes kStorageLocation{*from_hex(
    "0000000000000000000000000000000000000000000000000000000000000000")};

static const Bytes kBinaryCode{*from_hex("0x60045e005c60016000555d")};
static const evmc::bytes32 kCodeHash{0xef722d9baf50b9983c2fce6329c5a43a15b8d5ba79cd792e7199d615be88284d_bytes32};

class StateReaderTest : public silkworm::test_util::ContextTestBase {
  protected:
    db::test_util::MockTransaction transaction_;
    StateReader state_reader_{transaction_, kEarliestBlockNumber};
};

TEST_CASE_METHOD(StateReaderTest, "StateReader::read_account") {
    EXPECT_CALL(transaction_, first_txn_num_in_block(0)).WillOnce(Invoke([]() -> Task<TxnId> {
        co_return 0;
    }));

    SECTION("no account for history empty and current state empty") {
        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));

        // Execute the test: calling read_account should return no account
        std::optional<Account> account;
        CHECK_NOTHROW(account = spawn_and_wait(state_reader_.read_account(kZeroAddress)));
        CHECK(!account);
    }

    SECTION("account found in current state") {
        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = true,
                .value = kEncodedAccount};
            co_return response;
        }));

        // Execute the test: calling read_account should return the expected account
        std::optional<Account> account;
        CHECK_NOTHROW(account = spawn_and_wait(state_reader_.read_account(kZeroAddress)));
        CHECK(account);
        if (account) {
            CHECK(account->nonce == 2);
            CHECK(account->balance == 1000);
            CHECK(account->code_hash == 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32);
            CHECK(account->incarnation == 5);
        }
    }

    SECTION("account found in history") {
        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = true,
                .value = kEncodedAccount};
            co_return response;
        }));

        // Execute the test: calling read_account should return expected account
        std::optional<Account> account;
        CHECK_NOTHROW(account = spawn_and_wait(state_reader_.read_account(kZeroAddress)));
        CHECK(account);
        if (account) {
            CHECK(account->nonce == 2);
            CHECK(account->balance == 1000);
            CHECK(account->code_hash == 0xf1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c9239_bytes32);
            CHECK(account->incarnation == 5);
        }
    }
}

TEST_CASE_METHOD(StateReaderTest, "StateReader::read_storage") {
    EXPECT_CALL(transaction_, first_txn_num_in_block(0)).WillOnce(Invoke([]() -> Task<TxnId> {
        co_return 0;
    }));

    SECTION("empty storage for history empty and current state empty") {
        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));

        // Execute the test: calling read_storage should return empty storage value
        evmc::bytes32 location;
        CHECK_NOTHROW(location = spawn_and_wait(state_reader_.read_storage(kZeroAddress, 0, kLocationHash)));
        CHECK(location == evmc::bytes32{});
    }

    SECTION("storage found in current state") {
        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = true,
                .value = kStorageLocation};
            co_return response;
        }));
        // Execute the test: calling read_storage should return expected storage location
        evmc::bytes32 location;
        CHECK_NOTHROW(location = spawn_and_wait(state_reader_.read_storage(kZeroAddress, 0, kLocationHash)));
        CHECK(location == to_bytes32(kStorageLocation));
    }

    SECTION("storage found in history") {
        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = true,
                .value = kStorageLocation};
            co_return response;
        }));

        // Execute the test: calling read_storage should return expected storage location
        evmc::bytes32 location;
        CHECK_NOTHROW(location = spawn_and_wait(state_reader_.read_storage(kZeroAddress, 0, kLocationHash)));
        CHECK(location == to_bytes32(kStorageLocation));
    }
}

TEST_CASE_METHOD(StateReaderTest, "StateReader::read_code") {
    SECTION("no code for empty code hash") {
        // Execute the test: calling read_code should return no code for empty hash
        std::optional<Bytes> code;
        CHECK_NOTHROW(code = spawn_and_wait(state_reader_.read_code(kZeroAddress, kEmptyHash)));
        CHECK(!code);
    }

    SECTION("empty code found for code hash") {
        EXPECT_CALL(transaction_, first_txn_num_in_block(0)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 0;
        }));

        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));

        // Execute the test: calling read_code should return an empty code
        std::optional<Bytes> code;
        CHECK_NOTHROW(code = spawn_and_wait(state_reader_.read_code(kZeroAddress, kCodeHash)));
        CHECK(code);
        if (code) {
            CHECK(code->empty());
        }
    }

    SECTION("non-empty code found for code hash") {
        EXPECT_CALL(transaction_, first_txn_num_in_block(0)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 0;
        }));

        EXPECT_CALL(transaction_, get_latest(_)).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::DomainPointResult> {
            db::kv::api::DomainPointResult response{
                .success = true,
                .value = kBinaryCode};
            co_return response;
        }));

        // Execute the test: calling read_code should return a non-empty code
        std::optional<Bytes> code;
        CHECK_NOTHROW(code = spawn_and_wait(state_reader_.read_code(kZeroAddress, kCodeHash)));
        CHECK(code);
        if (code) {
            CHECK(to_hex(*code) == to_hex(kBinaryCode));
        }
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::db::state
