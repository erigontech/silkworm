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

#include "evm_debug.hpp"

#include <string>

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/thread_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/transaction.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/mock_block_cache.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>

namespace silkworm::rpc::debug {

using namespace silkworm::db;

struct DebugExecutorTest : public test_util::ServiceContextTestBase {
    test::MockBlockCache cache;
    db::test_util::MockTransaction transaction;
    WorkerPool workers{1};
    StringWriter writer{4096};
    boost::asio::any_io_executor io_executor{ioc_.get_executor()};
    json::Stream stream{io_executor, writer};
    test::BackEndMock backend;
    RemoteChainStorage chain_storage{transaction, ethdb::kv::make_backend_providers(&backend)};
};

class TestDebugExecutor : DebugExecutor {
  public:
    explicit TestDebugExecutor(
        BlockCache& block_cache,
        WorkerPool& workers,
        kv::api::Transaction& tx,
        DebugConfig config = {})
        : DebugExecutor(block_cache, workers, tx, config) {}
    ~TestDebugExecutor() override = default;

    TestDebugExecutor(const TestDebugExecutor&) = delete;
    TestDebugExecutor& operator=(const TestDebugExecutor&) = delete;

    Task<void> exec(json::Stream& stream, const ChainStorage& storage, const silkworm::Block& block, const Call& call) {
        return DebugExecutor::execute(stream, storage, block, call);
    }
};

#ifndef SILKWORM_SANITIZE
using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Unused;
using namespace evmc::literals;

static const evmc::bytes32 kZeroHeaderHash{0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a_bytes32};
static const Bytes kConfigKey{kZeroHeaderHash.bytes, kHashLength};
static const Bytes kConfigValue{string_view_to_byte_view(kSepoliaConfig.to_json().dump())};  // NOLINT(cppcoreguidelines-interfaces-global-init)

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute precompiled") {
    static Bytes account_history_key1{*silkworm::from_hex("0a6bb546b9208cfab9e8fa2b9b2c042b18df7030")};
    static Bytes account_history_key2{*silkworm::from_hex("0000000000000000000000000000000000000009")};
    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};

    static Bytes account_history_value1{*silkworm::from_hex("010203ed03e820f1885eda54b7a053318cd41e2093220dab15d65381b1157a3633a83bfd5c92390105")};

    SECTION("precompiled contract failure") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(10'336'007)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult rsp1{
                .success = true,
                .value = account_history_value1};
            co_return rsp1;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult rsp1{
                .success = true,
                .value = Bytes{}};
            co_return rsp1;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult rsp1{
                .success = true,
                .value = Bytes{}};
            co_return rsp1;
        }));

        evmc::address blake2f_precompile{0x0000000000000000000000000000000000000009_address};

        Call call;
        call.from = 0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address;
        call.to = blake2f_precompile;
        call.gas = 50'000;
        call.gas_price = 7;

        silkworm::Block block{};
        block.header.number = 10'336'006;

        TestDebugExecutor executor{cache, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
            "result": {
                "failed":true,
                "gas":50000,
                "returnValue":"",
                "structLogs":[]
            }
        })"_json);
    }
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute call 1") {
    static Bytes account_history_key1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes account_history_value1{*silkworm::from_hex("0203430b141e903194951083c424fd0000")};

    static Bytes account_history_key2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e556")};

    static Bytes account_history_key3{*silkworm::from_hex("0x0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("000944ed67f28fd50bb8e90000")};

    SECTION("Call: failed with intrinsic gas too low") {
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(_)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 50'000;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");
        silkworm::Block block{};
        block.header.number = block_num;

        TestDebugExecutor executor{cache, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "error":
          {
            "code": -32000,
            "message": "tracing failed: intrinsic gas too low: have 50000, want 53072"
          },
          "result":
          {
            "structLogs":
            []
          }
        })"_json);
    }

    SECTION("Call: full output") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };

        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_num;

        TestDebugExecutor executor{cache, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs":
            [
              {
                "depth": 1,
                "gas": 65864,
                "gasCost": 3,
                "memory":
                [],
                "op": "PUSH1",
                "pc": 0,
                "stack":
                []
              },
              {
                "depth": 1,
                "gas": 65861,
                "gasCost": 3,
                "memory":
                [],
                "op": "PUSH1",
                "pc": 2,
                "stack":
                [
                  "0x2a"
                ]
              },
              {
                "depth": 1,
                "gas": 65858,
                "gasCost": 22100,
                "memory":
                [],
                "op": "SSTORE",
                "pc": 4,
                "stack":
                [
                  "0x2a",
                  "0x0"
                ],
                "storage":
                {
                  "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000002a"
                }
              },
              {
                "depth": 1,
                "gas": 43758,
                "gasCost": 0,
                "memory":
                [],
                "op": "STOP",
                "pc": 5,
                "stack":
                []
              }
            ]
          }
        })"_json);
    }

    SECTION("Call: no stack") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_num;

        DebugConfig config{false, false, true};
        TestDebugExecutor executor{cache, workers, transaction, config};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs":
            [
              {
                "depth": 1,
                "gas": 65864,
                "gasCost": 3,
                "memory":
                [],
                "op": "PUSH1",
                "pc": 0
              },
              {
                "depth": 1,
                "gas": 65861,
                "gasCost": 3,
                "memory":
                [],
                "op": "PUSH1",
                "pc": 2
              },
              {
                "depth": 1,
                "gas": 65858,
                "gasCost": 22100,
                "memory":
                [],
                "op": "SSTORE",
                "pc": 4,
                "storage":
                {
                  "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000002a"
                }
              },
              {
                "depth": 1,
                "gas": 43758,
                "gasCost": 0,
                "memory":
                [],
                "op": "STOP",
                "pc": 5
              }
            ]
          }
        })"_json);
    }

    SECTION("Call: no memory") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_num;

        DebugConfig config{false, true, false};
        TestDebugExecutor executor{cache, workers, transaction, config};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs":
            [
              {
                "depth": 1,
                "gas": 65864,
                "gasCost": 3,
                "op": "PUSH1",
                "pc": 0,
                "stack":
                []
              },
              {
                "depth": 1,
                "gas": 65861,
                "gasCost": 3,
                "op": "PUSH1",
                "pc": 2,
                "stack":
                [
                  "0x2a"
                ]
              },
              {
                "depth": 1,
                "gas": 65858,
                "gasCost": 22100,
                "op": "SSTORE",
                "pc": 4,
                "stack":
                [
                  "0x2a",
                  "0x0"
                ],
                "storage":
                {
                  "0000000000000000000000000000000000000000000000000000000000000000": "000000000000000000000000000000000000000000000000000000000000002a"
                }
              },
              {
                "depth": 1,
                "gas": 43758,
                "gasCost": 0,
                "op": "STOP",
                "pc": 5,
                "stack":
                []
              }
            ]
          }
        })"_json);
    }

    SECTION("Call: no storage") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_num;

        DebugConfig config{true, false, false};
        TestDebugExecutor executor{cache, workers, transaction, config};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs":
            [
              {
                "depth": 1,
                "gas": 65864,
                "gasCost": 3,
                "memory":
                [],
                "op": "PUSH1",
                "pc": 0,
                "stack":
                []
              },
              {
                "depth": 1,
                "gas": 65861,
                "gasCost": 3,
                "memory":
                [],
                "op": "PUSH1",
                "pc": 2,
                "stack":
                [
                  "0x2a"
                ]
              },
              {
                "depth": 1,
                "gas": 65858,
                "gasCost": 22100,
                "memory":
                [],
                "op": "SSTORE",
                "pc": 4,
                "stack":
                [
                  "0x2a",
                  "0x0"
                ]
              },
              {
                "depth": 1,
                "gas": 43758,
                "gasCost": 0,
                "memory":
                [],
                "op": "STOP",
                "pc": 5,
                "stack":
                []
              }
            ]
          }
        })"_json);
    }

    SECTION("Call: no stack, memory and storage") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_num;

        DebugConfig config{true, true, true};
        TestDebugExecutor executor{cache, workers, transaction, config};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs":
            [
              {
                "depth": 1,
                "gas": 65864,
                "gasCost": 3,
                "op": "PUSH1",
                "pc": 0
              },
              {
                "depth": 1,
                "gas": 65861,
                "gasCost": 3,
                "op": "PUSH1",
                "pc": 2
              },
              {
                "depth": 1,
                "gas": 65858,
                "gasCost": 22100,
                "op": "SSTORE",
                "pc": 4
              },
              {
                "depth": 1,
                "gas": 43758,
                "gasCost": 0,
                "op": "STOP",
                "pc": 5
              }
            ]
          }
        })"_json);
    }

    SECTION("Call with stream") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7
        Call call;
        call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        call.gas = 118'936;
        call.gas_price = 7;
        call.data = *silkworm::from_hex("602a60005500");

        silkworm::Block block{};
        block.header.number = block_num;

        DebugConfig config{true, true, true};
        TestDebugExecutor executor{cache, workers, transaction, config};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 75178,
            "returnValue": "",
            "structLogs":
            [
              {
                "depth": 1,
                "gas": 65864,
                "gasCost": 3,
                "op": "PUSH1",
                "pc": 0
              },
              {
                "depth": 1,
                "gas": 65861,
                "gasCost": 3,
                "op": "PUSH1",
                "pc": 2
              },
              {
                "depth": 1,
                "gas": 65858,
                "gasCost": 22100,
                "op": "SSTORE",
                "pc": 4
              },
              {
                "depth": 1,
                "gas": 43758,
                "gasCost": 0,
                "op": "STOP",
                "pc": 5
              }
            ]
          }
        })"_json);
    }
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute call 2") {
    static Bytes account_history_key1{*silkworm::from_hex("8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9")};
    static Bytes account_history_value1{*silkworm::from_hex("03038c330a01a098914888dc0516d20000")};

    static Bytes account_history_key2{*silkworm::from_hex("5e1f0c9ddbe3cb57b80c933fab5151627d7966fa")};
    static Bytes account_history_value2{*silkworm::from_hex("010408014219564ff26a000000")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("00094165832d46fa1082db0000")};

    SECTION("Call: TO present") {
        db::kv::api::GetAsOfQuery query1{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query2{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfQuery query3{
            .table = table::kAccountDomain,
            .key = db::account_domain_key(bytes_to_address(account_history_key3)),
            .timestamp = 244087591818874,
        };
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));
        EXPECT_CALL(transaction, first_txn_num_in_block(4'417'197)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value2};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        const BlockNum block_num = 4'417'196;  // 0x4366AC
        Call call;
        call.from = 0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9_address;
        call.to = 0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa_address;
        call.value = 50'000'000;
        call.gas = 30'000;
        call.gas_price = 1'000'000'000;
        call.data = *silkworm::from_hex("00");

        silkworm::Block block{};
        block.header.number = block_num;

        TestDebugExecutor executor{cache, workers, transaction};

        stream.open_object();
        spawn_and_wait(executor.exec(stream, chain_storage, block, call));
        stream.close_object();
        spawn_and_wait(stream.close());

        nlohmann::json json = nlohmann::json::parse(writer.get_content());

        CHECK(json == R"({
          "result":
          {
            "failed": false,
            "gas": 21004,
            "returnValue": "",
            "structLogs":
            []
          }
        })"_json);
    }
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugExecutor::execute call with error") {
    static Bytes account_history_key1{*silkworm::from_hex("578f0a154b23be77fc2033197fbc775637648ad4")};
    static Bytes account_history_value1{*silkworm::from_hex("012f090207fbc719f215d7050000")};

    static Bytes account_history_key2{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("000944ed67f28fd50bb8e90000")};

    db::kv::api::GetAsOfQuery query1{
        .table = table::kAccountDomain,
        .key = db::account_domain_key(bytes_to_address(account_history_key1)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfQuery query2{
        .table = table::kAccountDomain,
        .key = db::account_domain_key(bytes_to_address(account_history_key2)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfQuery query3{
        .table = table::kAccountDomain,
        .key = db::account_domain_key(bytes_to_address(account_history_key3)),
        .timestamp = 244087591818874,
    };
    EXPECT_CALL(backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));
    EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kConfigValue;
        }));
    EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).WillOnce(Invoke([]() -> Task<TxnId> {
        co_return 244087591818873;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = account_history_value1};
        co_return response;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = Bytes{}};
        co_return response;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillOnce(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = account_history_value3};
        co_return response;
    }));

    BlockNum block_num = 5'405'095;  // 0x5279A7

    Call call;
    call.from = 0x578f0a154b23be77fc2033197fbc775637648ad4_address;
    call.value = 0;
    call.gas = 211'190;
    call.gas_price = 14;
    call.data = *silkworm::from_hex(
        "0x414bf3890000000000000000000000009d381f0b1637475f133c92d9b9fdc5493ae19b630000000000000000000000009b73fc19"
        "3bfa16abe18d1ea30734e4a6444a753f00000000000000000000000000000000000000000000000000000000000027100000000000"
        "00000000000000578f0a154b23be77fc2033197fbc775637648ad40000000000000000000000000000000000000000000000000000"
        "0000612ba19c00000000000000000000000000000000000000000001a784379d99db42000000000000000000000000000000000000"
        "00000000000002cdc48e6cca575707722c0000000000000000000000000000000000000000000000000000000000000000");

    silkworm::Block block{};
    block.header.number = block_num;

    TestDebugExecutor executor{cache, workers, transaction};

    stream.open_object();
    spawn_and_wait(executor.exec(stream, chain_storage, block, call));
    stream.close_object();
    spawn_and_wait(stream.close());

    nlohmann::json json = nlohmann::json::parse(writer.get_content());

    CHECK(json == R"({
      "result":
      {
        "failed": true,
        "gas": 211190,
        "returnValue": "",
        "structLogs":
        [
          {
            "depth": 1,
            "gas": 156082,
            "gasCost": 2,
            "memory":
            [],
            "op": "COINBASE",
            "pc": 0,
            "stack":
            []
          },
          {
            "depth": 1,
            "gas": 156080,
            "gasCost": 0,
            "memory":
            [],
            "op": "opcode 0x4b not defined",
            "pc": 1,
            "stack":
            [
              "0x0"
            ]
          }
        ]
      }
    })"_json);
}

TEST_CASE_METHOD(DebugExecutorTest, "DebugConfig") {
    SECTION("json deserialization") {
        nlohmann::json json = R"({
            "disableStorage": true,
            "disableMemory": false,
            "disableStack": true
            })"_json;

        DebugConfig config;
        from_json(json, config);

        CHECK(config.disable_storage == true);
        CHECK(config.disable_memory == false);
        CHECK(config.disable_stack == true);
    }
    SECTION("dump on stream") {
        DebugConfig config{true, false, true};

        std::ostringstream os;
        os << config;
        CHECK(os.str() == "disableStorage: true disableMemory: false disableStack: true NoRefunds: false");
    }
}

TEST_CASE("uint256_to_hex", "evmone::uint256") {
    SECTION("test 1") {
        evmone::uint256 v{0xB0A0};
        const std::string intx_hex{"0x" + intx::to_string(v, 16)};

        std::string hex{uint256_to_hex(v)};

        CHECK(intx_hex == hex);
    }
    SECTION("test 2") {
        evmone::uint256 v{0xCB0A0};
        const std::string intx_hex{"0x" + intx::to_string(v, 16)};

        std::string hex{uint256_to_hex(v)};

        CHECK(intx_hex == hex);
    }
}

#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::debug
