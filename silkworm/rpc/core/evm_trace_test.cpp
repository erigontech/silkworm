// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "evm_trace.hpp"

#include <string>
#include <utility>

#include <boost/asio/thread_pool.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/instructions.h>
#include <gmock/gmock.h>

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/db/chain/remote_chain_storage.hpp>
#include <silkworm/db/kv/api/endpoint/key_value.hpp>
#include <silkworm/db/tables.hpp>
#include <silkworm/db/test_util/mock_transaction.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/rpc/ethdb/kv/backend_providers.hpp>
#include <silkworm/rpc/test_util/mock_back_end.hpp>
#include <silkworm/rpc/test_util/mock_block_cache.hpp>
#include <silkworm/rpc/test_util/service_context_test_base.hpp>
#include <silkworm/rpc/types/transaction.hpp>

namespace silkworm::rpc::trace {

using namespace silkworm::db;
using chain::RemoteChainStorage;

struct TraceCallExecutorTest : public test_util::ServiceContextTestBase {
    db::test_util::MockTransaction transaction;
    WorkerPool workers{1};
    test::MockBlockCache block_cache;
    StringWriter writer{4096};
    boost::asio::any_io_executor io_executor{ioc_.get_executor()};
    test::BackEndMock backend;
    RemoteChainStorage chain_storage{transaction, ethdb::kv::make_backend_providers(&backend)};
};

#ifndef SILKWORM_SANITIZE
using testing::_;
using testing::Invoke;
using testing::InvokeWithoutArgs;
using testing::Unused;

static const evmc::bytes32 kZeroHeaderHash{0xbf7e331f7f7c1dd2e05159666b3bf8bc7a8a3a9eb1d518969eab529dd9b88c1a_bytes32};
static const Bytes kConfigKey{kZeroHeaderHash.bytes, kHashLength};
static const Bytes kConfigValue{string_view_to_byte_view(kSepoliaConfig.to_json().dump())};  // NOLINT(cppcoreguidelines-interfaces-global-init)

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call precompiled") {
    static Bytes account_history_key1{*silkworm::from_hex("0a6bb546b9208cfab9e8fa2b9b2c042b18df7030")};
    static Bytes account_history_key2{*silkworm::from_hex("0000000000000000000000000000000000000009")};
    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};

    SECTION("precompiled contract failure") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, first_txn_num_in_block(10'336'007)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult rsp1{
                .success = false,
                .value = Bytes{}};
            co_return rsp1;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult rsp1{
                .success = false,
                .value = Bytes{}};
            co_return rsp1;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult rsp1{
                .success = false,
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

        TraceConfig config{true, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(!result.pre_check_error);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                    "balance":{
                        "+":"0x55730"
                    },
                    "code":{
                        "+":"0x"
                    },
                    "nonce":{
                        "+":"0x0"
                    },
                    "storage":{}
                },
                "0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030":{
                    "balance":{
                        "+":"0x0"
                    },
                    "code":{
                        "+":"0x"
                    },
                    "nonce":{
                        "+":"0x1"
                    },
                    "storage":{}
                }
            },
            "trace":[],
            "vmTrace": {
                "code": "0x",
                "ops": []
            }
        })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call 1") {
    static Bytes account_history_key1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c7")};
    static Bytes account_history_value1{*silkworm::from_hex("0203430b141e903194951083c424fd0000")};

    static Bytes account_history_key2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e556")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("000944ed67f28fd50bb8e90000")};

    SECTION("Call: failed with intrinsic gas too low") {
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
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

        TraceConfig config{false, false, false};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == true);
        CHECK(result.pre_check_error.value() == "intrinsic gas too low: have 50000, want 53072");
    }

    SECTION("Call: full output") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
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

        TraceConfig config{true, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x44ed67f28fd50bb8e9",
                    "to": "0x44ed67f28fd513c08f"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                    "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                "balance": "=",
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x343",
                    "to": "0x344"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                },
                "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x2a"
                    ],
                    "store": null,
                    "used": 65861
                    },
                    "idx": "0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 65858
                    },
                    "idx": "1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 22100,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x2a"
                    },
                    "used": 43758
                    },
                    "idx": "2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 43758
                    },
                    "idx": "3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: no vmTrace") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
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

        TraceConfig config{false, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x44ed67f28fd50bb8e9",
                    "to": "0x44ed67f28fd513c08f"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                    "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                "balance": "=",
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x343",
                    "to": "0x344"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                },
                "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": null
        })"_json);
    }

    SECTION("Call: no trace") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
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

        TraceConfig config{true, false, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x44ed67f28fd50bb8e9",
                    "to": "0x44ed67f28fd513c08f"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                    "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                "balance": "=",
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x343",
                    "to": "0x344"
                    }
                },
                "storage": {}
                }
            },
            "trace": [],
            "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x2a"
                    ],
                    "store": null,
                    "used": 65861
                    },
                    "idx": "0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 65858
                    },
                    "idx": "1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 22100,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x2a"
                    },
                    "used": 43758
                    },
                    "idx": "2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 43758
                    },
                    "idx": "3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: no stateDiff") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
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

        TraceConfig config{true, true, false};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": null,
            "trace": [
                {
                "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                },
                "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x2a"
                    ],
                    "store": null,
                    "used": 65861
                    },
                    "idx": "0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 65858
                    },
                    "idx": "1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 22100,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x2a"
                    },
                    "used": 43758
                    },
                    "idx": "2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 43758
                    },
                    "idx": "3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: no vmTrace, trace and stateDiff") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
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

        TraceConfig config{false, false, false};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": null,
            "trace": [],
            "vmTrace": null
        })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call 2") {
    static Bytes account_history_key1{*silkworm::from_hex("8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9")};
    static Bytes account_history_value1{*silkworm::from_hex("03038c330a01a098914888dc0516d20000")};

    static Bytes account_history_key2{*silkworm::from_hex("5e1f0c9ddbe3cb57b80c933fab5151627d7966fa")};
    static Bytes account_history_value2{*silkworm::from_hex("010408014219564ff26a000000")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};

    SECTION("Call: TO present") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, first_txn_num_in_block(4'417'197)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
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
        EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
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

        TraceConfig config{true, true, true};
        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

        const auto result = spawn_and_wait(executor.trace_call(block, call, config));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"({
            "output": "0x",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "+": "0x131a5ff57800"
                },
                "code": {
                    "+": "0x"
                },
                "nonce": {
                    "+": "0x0"
                },
                "storage": {}
                },
                "0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa": {
                "balance": {
                    "*": {
                    "from": "0x14219564ff26a00",
                    "to": "0x142195652ed5a80"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9": {
                "balance": {
                    "*": {
                    "from": "0x1a098914888dc0516d2",
                    "to": "0x1a098914888d90a2652"
                    }
                },
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x38c33",
                    "to": "0x38c34"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "callType": "call",
                    "from": "0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9",
                    "gas": "0x2324",
                    "input": "0x00",
                    "to": "0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa",
                    "value": "0x2faf080"
                },
                "result": {
                    "gasUsed": "0x0",
                    "output": "0x"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "call"
                }
            ],
            "vmTrace": {
                "code": "0x",
                "ops": []
            }
        })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_call with error") {
    static Bytes account_history_key1{*silkworm::from_hex("578f0a154b23be77fc2033197fbc775637648ad4")};
    static Bytes account_history_value1{*silkworm::from_hex("012f090207fbc719f215d7050000")};

    static Bytes account_history_key2{*silkworm::from_hex("6951c35e335fa18c97cb207119133cd8009580cd")};
    static Bytes account_history_value2{*silkworm::from_hex("00000000")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("000944ed67f28fd50bb8e90000")};

    db::kv::api::GetAsOfRequest query1{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key1)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query2{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key2)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query3{
        .table = std::string{table::kAccountDomain},
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
    EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
        co_return 244087591818873;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
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
    EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
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

    TraceConfig config{true, true, true};
    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
    const auto result = spawn_and_wait(executor.trace_call(block, call, config));

    CHECK(result.pre_check_error.has_value() == false);
    CHECK(nlohmann::json(result.traces) == R"({
        "output": "0x",
        "stateDiff": {
            "0x0000000000000000000000000000000000000000": {
            "balance": {
                "*": {
                "from": "0x44ed67f28fd50bb8e9",
                "to": "0x44ed67f28fd538d65d"
                }
            },
            "code": "=",
            "nonce": "=",
            "storage": {}
            },
            "0x578f0a154b23be77fc2033197fbc775637648ad4": {
            "balance": "=",
            "code": "=",
            "nonce": {
                "*": {
                "from": "0x2f",
                "to": "0x30"
                }
            },
            "storage": {}
            }
        },
        "trace": [
            {
            "action": {
                "callType": "call",
                "from": "0x578f0a154b23be77fc2033197fbc775637648ad4",
                "gas": "0x261b2",
                "input": "0x",
                "to": "0x6951c35e335fa18c97cb207119133cd8009580cd",
                "value": "0x0"
            },
            "error": "invalid opcode: opcode 0x4b not defined",
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "call"
            }
        ],
        "vmTrace": {
            "code": "0x414bf3890000000000000000000000009d381f0b1637475f133c92d9b9fdc5493ae19b630000000000000000000000009b73fc193bfa16abe18d1ea30734e4a6444a753f0000000000000000000000000000000000000000000000000000000000002710000000000000000000000000578f0a154b23be77fc2033197fbc775637648ad400000000000000000000000000000000000000000000000000000000612ba19c00000000000000000000000000000000000000000001a784379d99db4200000000000000000000000000000000000000000000000002cdc48e6cca575707722c0000000000000000000000000000000000000000000000000000000000000000",
            "ops": [
            {
                "cost": 2,
                "ex": {
                "mem": null,
                "push": ["0x0"],
                "store": null,
                "used": 156080
                },
                "idx": "0",
                "op": "COINBASE",
                "pc": 0,
                "sub": null
            },
            {
                "cost": 0,
                "ex": {
                "mem": null,
                "push": [],
                "store": null,
                "used": 156080
                },
                "idx": "1",
                "op": "opcode 0x4b not defined",
                "pc": 1,
                "sub": null
            }
            ]
        }
    })"_json);
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_calls") {
    static Bytes account_history_key1{*silkworm::from_hex("e0a2bd4258d2768837baa26a28fe71dc079f84c700000000005279a8")};
    static Bytes account_history_value1{*silkworm::from_hex("0203430b141e903194951083c424fd0000")};

    static Bytes account_history_key2{*silkworm::from_hex("52728289eba496b6080d57d0250a90663a07e55600000000005279a8")};

    static Bytes account_history_key3{*silkworm::from_hex("000000000000000000000000000000000000000000000000005279a8")};
    static Bytes account_history_value3{*silkworm::from_hex("000944ed67f28fd50bb8e90000")};

    SECTION("callMany: failed with intrinsic gas too low") {
        EXPECT_CALL(transaction, first_txn_num_in_block(5'405'096)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(backend, get_block_hash_from_block_num(_))
            .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
                co_return kZeroHeaderHash;
            }));
        EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
            .WillOnce(InvokeWithoutArgs([]() -> Task<Bytes> {
                co_return kConfigValue;
            }));

        const BlockNum block_num = 5'405'095;  // 0x5279A7

        TraceCall trace_call;
        trace_call.call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        trace_call.call.gas = 50'000;
        trace_call.call.gas_price = 7;
        trace_call.call.data = *silkworm::from_hex("602a60005500");
        trace_call.trace_config = TraceConfig{false, false, false};

        std::vector<TraceCall> calls;
        calls.push_back(trace_call);

        silkworm::Block block{};
        block.header.number = block_num;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_calls(block, calls));

        CHECK(result.pre_check_error.has_value() == true);
        CHECK(result.pre_check_error.value() == "first run for txIndex 0 error: intrinsic gas too low: have 50000, want 53072");
    }

    SECTION("Call: full output") {
        db::kv::api::GetAsOfRequest query1{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key1)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query2{
            .table = std::string{table::kAccountDomain},
            .key = db::account_domain_key(bytes_to_address(account_history_key2)),
            .timestamp = 244087591818874,
        };
        db::kv::api::GetAsOfRequest query3{
            .table = std::string{table::kAccountDomain},
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
        EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
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
        TraceCall trace_call;
        trace_call.call.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
        trace_call.call.gas = 118'936;
        trace_call.call.gas_price = 7;
        trace_call.call.data = *silkworm::from_hex("602a60005500");
        trace_call.trace_config = TraceConfig{true, true, true};

        std::vector<TraceCall> calls;
        calls.push_back(trace_call);

        silkworm::Block block{};
        block.header.number = block_num;

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        const auto result = spawn_and_wait(executor.trace_calls(block, calls));

        CHECK(result.pre_check_error.has_value() == false);
        CHECK(nlohmann::json(result.traces) == R"([
            {
                "output": "0x",
                "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                    "balance": {
                    "*": {
                        "from": "0x44ed67f28fd50bb8e9",
                        "to": "0x44ed67f28fd513c08f"
                    }
                    },
                    "code": "=",
                    "nonce": "=",
                    "storage": {}
                },
                "0x52728289eba496b6080d57d0250a90663a07e556": {
                    "balance": {
                    "+": "0x0"
                    },
                    "code": {
                    "+": "0x"
                    },
                    "nonce": {
                    "+": "0x1"
                    },
                    "storage": {
                    "0x0000000000000000000000000000000000000000000000000000000000000000": {
                        "+": "0x000000000000000000000000000000000000000000000000000000000000002a"
                    }
                    }
                },
                "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7": {
                    "balance": "=",
                    "code": "=",
                    "nonce": {
                    "*": {
                        "from": "0x343",
                        "to": "0x344"
                    }
                    },
                    "storage": {}
                }
                },
                "trace": [
                {
                    "action": {
                    "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                    "gas": "0x10148",
                    "init": "0x602a60005500",
                    "value": "0x0"
                    },
                    "result": {
                    "address": "0x52728289eba496b6080d57d0250a90663a07e556",
                    "code": "0x",
                    "gasUsed": "0x565a"
                    },
                    "subtraces": 0,
                    "traceAddress": [],
                    "type": "create"
                }
                ],
                "vmTrace": {
                "code": "0x602a60005500",
                "ops": [
                    {
                    "cost": 3,
                    "ex": {
                        "mem": null,
                        "push": [
                        "0x2a"
                        ],
                        "store": null,
                        "used": 65861
                    },
                    "idx": "0-0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                    },
                    {
                    "cost": 3,
                    "ex": {
                        "mem": null,
                        "push": [
                        "0x0"
                        ],
                        "store": null,
                        "used": 65858
                    },
                    "idx": "0-1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                    },
                    {
                    "cost": 22100,
                    "ex": {
                        "mem": null,
                        "push": [],
                        "store": {
                        "key": "0x0",
                        "val": "0x2a"
                        },
                        "used": 43758
                    },
                    "idx": "0-2",
                    "op": "SSTORE",
                    "pc": 4,
                    "sub": null
                    },
                    {
                    "cost": 0,
                    "ex": {
                        "mem": null,
                        "push": [],
                        "store": null,
                        "used": 43758
                    },
                    "idx": "0-3",
                    "op": "STOP",
                    "pc": 5,
                    "sub": null
                    }
                ]
                }
            }
        ])"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_block_transactions") {
    // TransactionDatabase::get: TABLE AccountHistory
    static Bytes account_history_key1{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes account_history_value1{*silkworm::from_hex("0127080334e1d62a9e34400000")};

    static Bytes account_history_key2{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("0008028ded68c33d14010000")};

    db::kv::api::GetAsOfRequest query1{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key1)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query2{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key2)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query3{
        .table = std::string{table::kAccountDomain},
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
    EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
        co_return 244087591818873;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = account_history_value1};
        co_return response;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = false,
            .value = Bytes{}};
        co_return response;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = account_history_value3};
        co_return response;
    }));

    BlockNum block_num = 1'024'165;  // 0xFA0A5

    silkworm::Block block{};
    block.header.number = block_num;

    silkworm::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;

    block.transactions.push_back(txn);

    TraceConfig config{true, true, true};
    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
    const auto result = spawn_and_wait(executor.trace_block_transactions(block, config));

    CHECK(nlohmann::json(result) == R"([
        {
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "stateDiff": {
            "0x0000000000000000000000000000000000000000": {
                "balance": {
                "*": {
                    "from": "0x28ded68c33d1401",
                    "to": "0x28e46f23db3ea01"
                }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
            },
            "0xa85b4c37cd8f447848d49851a1bb06d10d410c13": {
                "balance": {
                "+": "0x0"
                },
                "code": {
                "+": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032"
                },
                "nonce": {
                "+": "0x1"
                },
                "storage": {}
            },
            "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5": {
                "balance": {
                "*": {
                    "from": "0x334e1d62a9e3440",
                    "to": "0x334884cb0275e40"
                }
                },
                "code": "=",
                "nonce": {
                "*": {
                    "from": "0x27",
                    "to": "0x28"
                }
                },
                "storage": {}
            }
            },
            "trace": [
            {
                "action": {
                "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
                "gas": "0x46da7c",
                "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "value": "0x0"
                },
                "result": {
                "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
                "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "gasUsed": "0xa3ab"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
            }
            ],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "vmTrace": {
            "code": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "ops": [
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x80"
                    ],
                    "store": null,
                    "used": 4643449
                },
                "idx": "0-0",
                "op": "PUSH1",
                "pc": 0,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x40"
                    ],
                    "store": null,
                    "used": 4643446
                },
                "idx": "0-1",
                "op": "PUSH1",
                "pc": 2,
                "sub": null
                },
                {
                "cost": 12,
                "ex": {
                    "mem": {
                    "data": "0x0000000000000000000000000000000000000000000000000000000000000080",
                    "off": 64
                    },
                    "push": [],
                    "store": null,
                    "used": 4643434
                },
                "idx": "0-2",
                "op": "MSTORE",
                "pc": 4,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4643431
                },
                "idx": "0-3",
                "op": "PUSH1",
                "pc": 5,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0",
                    "0x0"
                    ],
                    "store": null,
                    "used": 4643428
                },
                "idx": "0-4",
                "op": "DUP1",
                "pc": 7,
                "sub": null
                },
                {
                "cost": 2200,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                    "key": "0x0",
                    "val": "0x0"
                    },
                    "used": 4641228
                },
                "idx": "0-5",
                "op": "SSTORE",
                "pc": 8,
                "sub": null
                },
                {
                "cost": 2,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641226
                },
                "idx": "0-6",
                "op": "CALLVALUE",
                "pc": 9,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0",
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641223
                },
                "idx": "0-7",
                "op": "DUP1",
                "pc": 10,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x1"
                    ],
                    "store": null,
                    "used": 4641220
                },
                "idx": "0-8",
                "op": "ISZERO",
                "pc": 11,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x14"
                    ],
                    "store": null,
                    "used": 4641217
                },
                "idx": "0-9",
                "op": "PUSH2",
                "pc": 12,
                "sub": null
                },
                {
                "cost": 10,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641207
                },
                "idx": "0-10",
                "op": "JUMPI",
                "pc": 15,
                "sub": null
                },
                {
                "cost": 1,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641206
                },
                "idx": "0-11",
                "op": "JUMPDEST",
                "pc": 20,
                "sub": null
                },
                {
                "cost": 2,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641204
                },
                "idx": "0-12",
                "op": "POP",
                "pc": 21,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0xc6"
                    ],
                    "store": null,
                    "used": 4641201
                },
                "idx": "0-13",
                "op": "PUSH1",
                "pc": 22,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0xc6",
                    "0xc6"
                    ],
                    "store": null,
                    "used": 4641198
                },
                "idx": "0-14",
                "op": "DUP1",
                "pc": 24,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x23"
                    ],
                    "store": null,
                    "used": 4641195
                },
                "idx": "0-15",
                "op": "PUSH2",
                "pc": 25,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641192
                },
                "idx": "0-16",
                "op": "PUSH1",
                "pc": 28,
                "sub": null
                },
                {
                "cost": 36,
                "ex": {
                    "mem": {
                    "data": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "off": 0
                    },
                    "push": [],
                    "store": null,
                    "used": 4641156
                },
                "idx": "0-17",
                "op": "CODECOPY",
                "pc": 30,
                "sub": null
                },
                {
                "cost": 3,
                "ex": {
                    "mem": null,
                    "push": [
                    "0x0"
                    ],
                    "store": null,
                    "used": 4641153
                },
                "idx": "0-18",
                "op": "PUSH1",
                "pc": 31,
                "sub": null
                },
                {
                "cost": 0,
                "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641153
                },
                "idx": "0-19",
                "op": "RETURN",
                "pc": 33,
                "sub": null
                }
            ]
            }
        }
    ])"_json);
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_block") {
    static Bytes account_history_key1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};

    static Bytes account_history_key2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value2{*silkworm::from_hex("0008028ded68c33d14010000")};

    static Bytes account_history_key3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes account_history_value3{*silkworm::from_hex("0127080334e1d62a9e34400000")};

    db::kv::api::GetAsOfRequest query1{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key1)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query2{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key2)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query3{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key3)),
        .timestamp = 244087591818874,
    };
    EXPECT_CALL(backend, get_block_hash_from_block_num(_))
        .Times(2)
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));
    EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kConfigValue;
        }));
    EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
        co_return 244087591818873;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = false,
            .value = Bytes{}};
        co_return response;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = account_history_value2};
        co_return response;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult response{
            .success = true,
            .value = account_history_value3};
        co_return response;
    }));

    BlockNum block_num = 1'024'165;  // 0xFA0A5

    silkworm::BlockWithHash block_with_hash;
    block_with_hash.block.header.number = block_num;
    block_with_hash.hash = 0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592_bytes32;

    silkworm::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;

    block_with_hash.block.transactions.push_back(txn);

    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};

    Filter filter;
    const auto result = spawn_and_wait(executor.trace_block(block_with_hash, filter));

    CHECK(nlohmann::json(result) == R"([
        {
            "action": {
            "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
            "gas": "0x46da7c",
            "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "value": "0x0"
            },
            "blockHash": "0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592",
            "blockNumber": 1024165,
            "result": {
            "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
            "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "gasUsed": "0xa3ab"
            },
            "subtraces": 0,
            "traceAddress": [],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "transactionPosition": 0,
            "type": "create"
        }
    ])"_json);
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_replayTransaction") {
    static Bytes account_history_key1{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes account_history_value1{*silkworm::from_hex("0127080334e1d62a9e34400000")};

    static Bytes account_history_key2{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};

    static Bytes account_history_key3{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value3{*silkworm::from_hex("0008028ded68c33d14010000")};

    db::kv::api::GetAsOfRequest query1{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key1)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query2{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key2)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query3{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key3)),
        .timestamp = 244087591818874,
    };
    EXPECT_CALL(backend, get_block_hash_from_block_num(_))
        .WillOnce(InvokeWithoutArgs([]() -> Task<std::optional<evmc::bytes32>> {
            co_return kZeroHeaderHash;
        }));
    EXPECT_CALL(transaction, get_one(table::kConfigName, silkworm::ByteView{kConfigKey}))
        .WillRepeatedly(InvokeWithoutArgs([]() -> Task<Bytes> {
            co_return kConfigValue;
        }));

    BlockNum block_num = 1'024'165;  // 0xFA0A5

    silkworm::BlockWithHash block_with_hash;
    block_with_hash.block.header.number = block_num;
    block_with_hash.hash = 0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592_bytes32;

    rpc::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;
    txn.block_hash = block_with_hash.hash;
    txn.block_num = block_num;
    txn.transaction_index = 0;

    block_with_hash.block.transactions.push_back(txn);

    SECTION("Call: only vmTrace") {
        EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).WillOnce(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query1})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query2})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query3})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = true, .trace = false, .state_diff = false};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "stateDiff": null,
            "trace": [],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "vmTrace": {
                "code": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x80"
                    ],
                    "store": null,
                    "used": 4643449
                    },
                    "idx": "0-0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x40"
                    ],
                    "store": null,
                    "used": 4643446
                    },
                    "idx": "0-1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 12,
                    "ex": {
                    "mem": {
                        "data": "0x0000000000000000000000000000000000000000000000000000000000000080",
                        "off": 64
                    },
                    "push": [],
                    "store": null,
                    "used": 4643434
                    },
                    "idx": "0-2",
                    "op": "MSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643431
                    },
                    "idx": "0-3",
                    "op": "PUSH1",
                    "pc": 5,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643428
                    },
                    "idx": "0-4",
                    "op": "DUP1",
                    "pc": 7,
                    "sub": null
                },
                {
                    "cost": 2200,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x0"
                    },
                    "used": 4641228
                    },
                    "idx": "0-5",
                    "op": "SSTORE",
                    "pc": 8,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641226
                    },
                    "idx": "0-6",
                    "op": "CALLVALUE",
                    "pc": 9,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641223
                    },
                    "idx": "0-7",
                    "op": "DUP1",
                    "pc": 10,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x1"
                    ],
                    "store": null,
                    "used": 4641220
                    },
                    "idx": "0-8",
                    "op": "ISZERO",
                    "pc": 11,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x14"
                    ],
                    "store": null,
                    "used": 4641217
                    },
                    "idx": "0-9",
                    "op": "PUSH2",
                    "pc": 12,
                    "sub": null
                },
                {
                    "cost": 10,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641207
                    },
                    "idx": "0-10",
                    "op": "JUMPI",
                    "pc": 15,
                    "sub": null
                },
                {
                    "cost": 1,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641206
                    },
                    "idx": "0-11",
                    "op": "JUMPDEST",
                    "pc": 20,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641204
                    },
                    "idx": "0-12",
                    "op": "POP",
                    "pc": 21,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641201
                    },
                    "idx": "0-13",
                    "op": "PUSH1",
                    "pc": 22,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6",
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641198
                    },
                    "idx": "0-14",
                    "op": "DUP1",
                    "pc": 24,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x23"
                    ],
                    "store": null,
                    "used": 4641195
                    },
                    "idx": "0-15",
                    "op": "PUSH2",
                    "pc": 25,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641192
                    },
                    "idx": "0-16",
                    "op": "PUSH1",
                    "pc": 28,
                    "sub": null
                },
                {
                    "cost": 36,
                    "ex": {
                    "mem": {
                        "data": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                        "off": 0
                    },
                    "push": [],
                    "store": null,
                    "used": 4641156
                    },
                    "idx": "0-17",
                    "op": "CODECOPY",
                    "pc": 30,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-18",
                    "op": "PUSH1",
                    "pc": 31,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-19",
                    "op": "RETURN",
                    "pc": 33,
                    "sub": null
                }
                ]
            }
        })"_json);
    }

    SECTION("Call: only trace") {
        EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query1})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query2})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query3})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = false, .trace = true, .state_diff = false};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "stateDiff": null,
            "trace": [
                {
                "action": {
                    "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
                    "gas": "0x46da7c",
                    "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "value": "0x0"
                },
                "result": {
                    "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
                    "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "gasUsed": "0xa3ab"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": null
        })"_json);
    }
    SECTION("Call: only stateDiff") {
        EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query1})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query2})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query3})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = false, .trace = false, .state_diff = true};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x28ded68c33d1401",
                    "to": "0x28e46f23db3ea01"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0xa85b4c37cd8f447848d49851a1bb06d10d410c13": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {}
                },
                "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5": {
                "balance": {
                    "*": {
                    "from": "0x334e1d62a9e3440",
                    "to": "0x334884cb0275e40"
                    }
                },
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x27",
                    "to": "0x28"
                    }
                },
                "storage": {}
                }
            },
            "trace": [],
            "vmTrace": null
        })"_json);
    }
    SECTION("Call: full output") {
        EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
            co_return 244087591818873;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query1})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value1};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query2})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = false,
                .value = Bytes{}};
            co_return response;
        }));
        EXPECT_CALL(transaction, get_as_of(silkworm::db::kv::api::GetAsOfRequest{query3})).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
            db::kv::api::GetAsOfResult response{
                .success = true,
                .value = account_history_value3};
            co_return response;
        }));

        TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
        TraceConfig config{.vm_trace = true, .trace = true, .state_diff = true};
        const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash.block, txn, config));

        CHECK(nlohmann::json(result) == R"({
            "output": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "stateDiff": {
                "0x0000000000000000000000000000000000000000": {
                "balance": {
                    "*": {
                    "from": "0x28ded68c33d1401",
                    "to": "0x28e46f23db3ea01"
                    }
                },
                "code": "=",
                "nonce": "=",
                "storage": {}
                },
                "0xa85b4c37cd8f447848d49851a1bb06d10d410c13": {
                "balance": {
                    "+": "0x0"
                },
                "code": {
                    "+": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032"
                },
                "nonce": {
                    "+": "0x1"
                },
                "storage": {}
                },
                "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5": {
                "balance": {
                    "*": {
                    "from": "0x334e1d62a9e3440",
                    "to": "0x334884cb0275e40"
                    }
                },
                "code": "=",
                "nonce": {
                    "*": {
                    "from": "0x27",
                    "to": "0x28"
                    }
                },
                "storage": {}
                }
            },
            "trace": [
                {
                "action": {
                    "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
                    "gas": "0x46da7c",
                    "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "value": "0x0"
                },
                "result": {
                    "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
                    "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                    "gasUsed": "0xa3ab"
                },
                "subtraces": 0,
                "traceAddress": [],
                "type": "create"
                }
            ],
            "vmTrace": {
                "code": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                "ops": [
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x80"
                    ],
                    "store": null,
                    "used": 4643449
                    },
                    "idx": "0-0",
                    "op": "PUSH1",
                    "pc": 0,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x40"
                    ],
                    "store": null,
                    "used": 4643446
                    },
                    "idx": "0-1",
                    "op": "PUSH1",
                    "pc": 2,
                    "sub": null
                },
                {
                    "cost": 12,
                    "ex": {
                    "mem": {
                        "data": "0x0000000000000000000000000000000000000000000000000000000000000080",
                        "off": 64
                    },
                    "push": [],
                    "store": null,
                    "used": 4643434
                    },
                    "idx": "0-2",
                    "op": "MSTORE",
                    "pc": 4,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643431
                    },
                    "idx": "0-3",
                    "op": "PUSH1",
                    "pc": 5,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4643428
                    },
                    "idx": "0-4",
                    "op": "DUP1",
                    "pc": 7,
                    "sub": null
                },
                {
                    "cost": 2200,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": {
                        "key": "0x0",
                        "val": "0x0"
                    },
                    "used": 4641228
                    },
                    "idx": "0-5",
                    "op": "SSTORE",
                    "pc": 8,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641226
                    },
                    "idx": "0-6",
                    "op": "CALLVALUE",
                    "pc": 9,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0",
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641223
                    },
                    "idx": "0-7",
                    "op": "DUP1",
                    "pc": 10,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x1"
                    ],
                    "store": null,
                    "used": 4641220
                    },
                    "idx": "0-8",
                    "op": "ISZERO",
                    "pc": 11,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x14"
                    ],
                    "store": null,
                    "used": 4641217
                    },
                    "idx": "0-9",
                    "op": "PUSH2",
                    "pc": 12,
                    "sub": null
                },
                {
                    "cost": 10,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641207
                    },
                    "idx": "0-10",
                    "op": "JUMPI",
                    "pc": 15,
                    "sub": null
                },
                {
                    "cost": 1,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641206
                    },
                    "idx": "0-11",
                    "op": "JUMPDEST",
                    "pc": 20,
                    "sub": null
                },
                {
                    "cost": 2,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641204
                    },
                    "idx": "0-12",
                    "op": "POP",
                    "pc": 21,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641201
                    },
                    "idx": "0-13",
                    "op": "PUSH1",
                    "pc": 22,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0xc6",
                        "0xc6"
                    ],
                    "store": null,
                    "used": 4641198
                    },
                    "idx": "0-14",
                    "op": "DUP1",
                    "pc": 24,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x23"
                    ],
                    "store": null,
                    "used": 4641195
                    },
                    "idx": "0-15",
                    "op": "PUSH2",
                    "pc": 25,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641192
                    },
                    "idx": "0-16",
                    "op": "PUSH1",
                    "pc": 28,
                    "sub": null
                },
                {
                    "cost": 36,
                    "ex": {
                    "mem": {
                        "data": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
                        "off": 0
                    },
                    "push": [],
                    "store": null,
                    "used": 4641156
                    },
                    "idx": "0-17",
                    "op": "CODECOPY",
                    "pc": 30,
                    "sub": null
                },
                {
                    "cost": 3,
                    "ex": {
                    "mem": null,
                    "push": [
                        "0x0"
                    ],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-18",
                    "op": "PUSH1",
                    "pc": 31,
                    "sub": null
                },
                {
                    "cost": 0,
                    "ex": {
                    "mem": null,
                    "push": [],
                    "store": null,
                    "used": 4641153
                    },
                    "idx": "0-19",
                    "op": "RETURN",
                    "pc": 33,
                    "sub": null
                }
                ]
            }
          })"_json);
    }
}

TEST_CASE_METHOD(TraceCallExecutorTest, "TraceCallExecutor::trace_transaction") {
    static Bytes account_history_key1{*silkworm::from_hex("a85b4c37cd8f447848d49851a1bb06d10d410c13")};

    static Bytes account_history_key2{*silkworm::from_hex("0000000000000000000000000000000000000000")};
    static Bytes account_history_value2{*silkworm::from_hex("0008028ded68c33d14010000")};

    static Bytes account_history_key3{*silkworm::from_hex("daae090d53f9ed9e2e1fd25258c01bac4dd6d1c5")};
    static Bytes account_history_value3{*silkworm::from_hex("0127080334e1d62a9e34400000")};

    db::kv::api::GetAsOfRequest query1{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key1)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query2{
        .table = std::string{table::kAccountDomain},
        .key = db::account_domain_key(bytes_to_address(account_history_key2)),
        .timestamp = 244087591818874,
    };
    db::kv::api::GetAsOfRequest query3{
        .table = std::string{table::kAccountDomain},
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
    EXPECT_CALL(transaction, first_txn_num_in_block(1'024'165)).Times(1).WillRepeatedly(Invoke([]() -> Task<TxnId> {
        co_return 244087591818873;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query1))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult rsp1{
            .success = false,
            .value = Bytes{}};
        co_return rsp1;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query2))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult rsp1{
            .success = true,
            .value = account_history_value2};
        co_return rsp1;
    }));
    EXPECT_CALL(transaction, get_as_of(std::move(query3))).WillRepeatedly(Invoke([=](Unused) -> Task<db::kv::api::GetAsOfResult> {
        db::kv::api::GetAsOfResult rsp1{
            .success = true,
            .value = account_history_value3};
        co_return rsp1;
    }));

    BlockNum block_num = 1'024'165;  // 0xFA0A5

    silkworm::BlockWithHash block_with_hash;
    block_with_hash.block.header.number = block_num;
    block_with_hash.hash = 0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592_bytes32;

    rpc::Transaction txn;
    txn.set_sender(0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5_address);
    txn.nonce = 27;
    txn.value = 0;
    txn.data = *silkworm::from_hex(
        "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004"
        "361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080"
        "fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060"
        "008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c"
        "60af2c64736f6c634300050a0032");
    txn.max_priority_fee_per_gas = 0x3b9aca00;
    txn.max_fee_per_gas = 0x3b9aca00;
    txn.gas_limit = 0x47b760;
    txn.type = TransactionType::kLegacy;
    txn.block_hash = block_with_hash.hash;
    txn.block_num = block_num;
    txn.transaction_index = 0;

    block_with_hash.block.transactions.push_back(txn);

    TraceCallExecutor executor{block_cache, chain_storage, workers, transaction};
    const auto result = spawn_and_wait(executor.trace_transaction(block_with_hash, txn, true));

    CHECK(nlohmann::json(result) == R"([
        {
            "action": {
            "from": "0xdaae090d53f9ed9e2e1fd25258c01bac4dd6d1c5",
            "gas": "0x46da7c",
            "init": "0x60806040526000805534801561001457600080fd5b5060c6806100236000396000f3fe6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "value": "0x0"
            },
            "blockHash": "0x527198f474c1f1f1d01129d3a17ecc17895d85884a31b05ef0ecd480faee1592",
            "blockNumber": 1024165,
            "result": {
            "address": "0xa85b4c37cd8f447848d49851a1bb06d10d410c13",
            "code": "0x6080604052348015600f57600080fd5b506004361060325760003560e01c806360fe47b11460375780636d4ce63c146062575b600080fd5b606060048036036020811015604b57600080fd5b8101908080359060200190929190505050607e565b005b60686088565b6040518082815260200191505060405180910390f35b8060008190555050565b6000805490509056fea265627a7a72305820ca7603d2458ae7a9db8bde091d8ba88a4637b54a8cc213b73af865f97c60af2c64736f6c634300050a0032",
            "gasUsed": "0xa3ab"
            },
            "subtraces": 0,
            "traceAddress": [],
            "transactionHash": "0x849ca3076047d76288f2d15b652f18e80622aa6163eff0a216a446d0a4a5288e",
            "transactionPosition": 0,
            "type": "create"
        }
    ])"_json);
}

TEST_CASE("VmTrace json serialization") {
    TraceEx trace_ex;
    trace_ex.used = 5000;
    trace_ex.stack.emplace_back("0xdeadbeaf");
    trace_ex.memory = TraceMemory{10, 0, "data"};
    trace_ex.storage = TraceStorage{"key", "value"};

    TraceOp trace_op;
    trace_op.gas_cost = 42;
    trace_op.trace_ex = trace_ex;
    trace_op.idx = "12";
    trace_op.op_name = "PUSH1";
    trace_op.pc = 27;
    VmTrace vm_trace;

    vm_trace.code = "0xdeadbeaf";
    vm_trace.ops.push_back(trace_op);

    SECTION("VmTrace") {
        CHECK(nlohmann::json(vm_trace) == R"({
            "code": "0xdeadbeaf",
            "ops": [
                {
                    "cost":42,
                    "ex":{
                        "mem": null,
                        "push":["0xdeadbeaf"],
                        "store":{
                            "key":"key",
                            "val":"value"
                        },
                        "used":5000
                    },
                    "idx":"12",
                    "op":"PUSH1",
                    "pc":27,
                    "sub":null
                }
            ]
        })"_json);
    }
    SECTION("TraceOp") {
        CHECK(nlohmann::json(trace_op) == R"({
            "cost":42,
            "ex":{
                "mem": null,
                "push":["0xdeadbeaf"],
                "store":{
                    "key":"key",
                    "val":"value"
                },
                "used":5000
            },
            "idx":"12",
            "op":"PUSH1",
            "pc":27,
            "sub":null
        })"_json);
    }
    SECTION("TraceEx") {
        CHECK(nlohmann::json(trace_ex) == R"({
            "mem": null,
            "push":["0xdeadbeaf"],
            "store":{
                "key":"key",
                "val":"value"
            },
            "used":5000
        })"_json);
    }
    SECTION("TraceMemory") {
        const auto& memory = trace_ex.memory.value();
        CHECK(nlohmann::json(memory) == R"({
            "data":"data",
            "off":10
        })"_json);
    }
    SECTION("TraceStorage") {
        const auto& storage = trace_ex.storage.value();
        CHECK(nlohmann::json(storage) == R"({
            "key":"key",
            "val":"value"
        })"_json);
    }
}

TEST_CASE("TraceAction json serialization") {
    TraceAction trace_action;
    trace_action.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
    trace_action.gas = 1000;
    trace_action.value = intx::uint256{0xdeadbeaf};

    SECTION("basic") {
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "gas": "0x3e8",
            "value": "0xdeadbeaf"
        })"_json);
    }
    SECTION("with to") {
        trace_action.to = 0xe0a2bd4258d2768837baa26a28fe71dc079f8aaa_address;
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "to": "0xe0a2bd4258d2768837baa26a28fe71dc079f8aaa",
            "gas": "0x3e8",
            "value": "0xdeadbeaf"
        })"_json);
    }
    SECTION("with input") {
        trace_action.input = *silkworm::from_hex("0xdeadbeaf");
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "gas": "0x3e8",
            "input": "0xdeadbeaf",
            "value": "0xdeadbeaf"
        })"_json);
    }
    SECTION("with init") {
        trace_action.init = *silkworm::from_hex("0xdeadbeaf");
        CHECK(nlohmann::json(trace_action) == R"({
            "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
            "gas": "0x3e8",
            "init": "0xdeadbeaf",
            "value": "0xdeadbeaf"
        })"_json);
    }
}

TEST_CASE("TraceResult json serialization") {
    TraceResult trace_result;
    trace_result.address = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
    trace_result.code = *silkworm::from_hex("0x1234567890abcdef");
    trace_result.gas_used = 1000;

    CHECK(nlohmann::json(trace_result) == R"({
        "address": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
        "code": "0x1234567890abcdef",
        "gasUsed": "0x3e8"
    })"_json);
}

TEST_CASE("Trace json serialization") {
    TraceAction trace_action;
    trace_action.from = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c7_address;
    trace_action.gas = 1000;
    trace_action.value = intx::uint256{0xdeadbeaf};

    Trace trace;
    trace.action = trace_action;
    trace.type = "CALL";

    SECTION("basic with trace action") {
        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "gas": "0x3e8",
                "value": "0xdeadbeaf"
            },
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "CALL"
        })"_json);
    }

    SECTION("basic with reward action") {
        RewardAction reward_action;
        reward_action.author = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84d8_address;
        reward_action.reward_type = "block";
        reward_action.value = intx::uint256{0xdeadbeaf};

        trace.action = reward_action;
        trace.type = "reward";

        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "author": "0xe0a2bd4258d2768837baa26a28fe71dc079f84d8",
                "rewardType": "block",
                "value": "0xdeadbeaf"
            },
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "reward"
        })"_json);
    }

    SECTION("with trace_result") {
        TraceResult trace_result;
        trace_result.address = 0xe0a2Bd4258D2768837BAa26A28fE71Dc079f84c8_address;
        trace_result.code = *silkworm::from_hex("0x1234567890abcdef");
        trace_result.gas_used = 1000;

        trace.trace_result = trace_result;

        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "gas": "0x3e8",
                "value": "0xdeadbeaf"
            },
            "result": {
                "address": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8",
                "code": "0x1234567890abcdef",
                "gasUsed": "0x3e8"
            },
            "subtraces": 0,
            "traceAddress": [],
            "type": "CALL"
        })"_json);
    }
    SECTION("with error") {
        trace.error = "error";

        CHECK(nlohmann::json(trace) == R"({
            "action": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "gas": "0x3e8",
                "value": "0xdeadbeaf"
            },
            "error": "error",
            "result": null,
            "subtraces": 0,
            "traceAddress": [],
            "type": "CALL"
        })"_json);
    }
}

TEST_CASE("StateDiff json serialization") {
    StateDiff state_diff;

    SECTION("basic") {
        CHECK(nlohmann::json(state_diff) == R"({
        })"_json);
    }
    SECTION("with 1 entry") {
        StateDiffEntry entry;

        state_diff.insert(std::pair<std::string, StateDiffEntry>("item", entry));

        CHECK(nlohmann::json(state_diff) == R"({
            "item": {
                "balance": "=",
                "code": "=",
                "nonce": "=",
                "storage": {}
            }
        })"_json);
    }
}

TEST_CASE("DiffValue json serialization") {
    SECTION("no entries") {
        DiffValue dv;

        CHECK(nlohmann::json(dv) == R"("=")"_json);
    }
    SECTION("only from entry") {
        DiffValue dv{"0xe0a2bd4258d2768837baa26a28fe71dc079f84c7"};

        CHECK(nlohmann::json(dv) == R"({
            "-":"0xe0a2bd4258d2768837baa26a28fe71dc079f84c7"
        })"_json);
    }
    SECTION("only to entry") {
        DiffValue dv{{}, "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"};

        CHECK(nlohmann::json(dv) == R"({
            "+": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"
        })"_json);
    }
    SECTION("both entries") {
        DiffValue dv{"0xe0a2bd4258d2768837baa26a28fe71dc079f84c7", "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"};

        CHECK(nlohmann::json(dv) == R"({
            "*": {
                "from": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c7",
                "to": "0xe0a2bd4258d2768837baa26a28fe71dc079f84c8"
            }
        })"_json);
    }
}

TEST_CASE("copy_stack") {
    const size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    SECTION("PUSHX") {
        for (std::uint8_t op_code = evmc_opcode::OP_PUSH1; op_code < evmc_opcode::OP_PUSH32 + 1; ++op_code) {
            std::vector<std::string> trace_stack;
            copy_stack(op_code, top_stack, trace_stack);

            CHECK(trace_stack.size() == 1);
            CHECK(trace_stack[0] == "0x1f");
        }
    }

    SECTION("OP_SWAPX") {
        for (std::uint8_t op_code = evmc_opcode::OP_SWAP1; op_code < evmc_opcode::OP_SWAP16 + 1; ++op_code) {
            std::vector<std::string> trace_stack;
            copy_stack(op_code, top_stack, trace_stack);

            std::uint8_t size = op_code - evmc_opcode::OP_SWAP1 + 2;
            CHECK(trace_stack.size() == size);
            for (size_t idx = 0; idx < size; ++idx) {
                CHECK(trace_stack[idx] == "0x" + intx::to_string(stack[stack_size - size + idx], 16));
            }
        }
    }

    SECTION("OP_DUPX") {
        for (std::uint8_t op_code = evmc_opcode::OP_DUP1; op_code < evmc_opcode::OP_DUP16 + 1; ++op_code) {
            std::vector<std::string> trace_stack;
            copy_stack(op_code, top_stack, trace_stack);

            std::uint8_t size = op_code - evmc_opcode::OP_DUP1 + 2;
            CHECK(trace_stack.size() == size);
            for (size_t idx = 0; idx < size; ++idx) {
                CHECK(trace_stack[idx] == "0x" + intx::to_string(stack[stack_size - size + idx], 16));
            }
        }
    }

    SECTION("OP_OTHER") {
        for (std::uint8_t op_code = evmc_opcode::OP_STOP; op_code < evmc_opcode::OP_SELFDESTRUCT; ++op_code) {
            std::vector<std::string> trace_stack;
            switch (op_code) {
                case evmc_opcode::OP_PUSH1:
                case evmc_opcode::OP_PUSH2:
                case evmc_opcode::OP_PUSH3:
                case evmc_opcode::OP_PUSH4:
                case evmc_opcode::OP_PUSH5:
                case evmc_opcode::OP_PUSH6:
                case evmc_opcode::OP_PUSH7:
                case evmc_opcode::OP_PUSH8:
                case evmc_opcode::OP_PUSH9:
                case evmc_opcode::OP_PUSH10:
                case evmc_opcode::OP_PUSH11:
                case evmc_opcode::OP_PUSH12:
                case evmc_opcode::OP_PUSH13:
                case evmc_opcode::OP_PUSH14:
                case evmc_opcode::OP_PUSH15:
                case evmc_opcode::OP_PUSH16:
                case evmc_opcode::OP_PUSH17:
                case evmc_opcode::OP_PUSH18:
                case evmc_opcode::OP_PUSH19:
                case evmc_opcode::OP_PUSH20:
                case evmc_opcode::OP_PUSH21:
                case evmc_opcode::OP_PUSH22:
                case evmc_opcode::OP_PUSH23:
                case evmc_opcode::OP_PUSH24:
                case evmc_opcode::OP_PUSH25:
                case evmc_opcode::OP_PUSH26:
                case evmc_opcode::OP_PUSH27:
                case evmc_opcode::OP_PUSH28:
                case evmc_opcode::OP_PUSH29:
                case evmc_opcode::OP_PUSH30:
                case evmc_opcode::OP_PUSH31:
                case evmc_opcode::OP_PUSH32:
                case evmc_opcode::OP_SWAP1:
                case evmc_opcode::OP_SWAP2:
                case evmc_opcode::OP_SWAP3:
                case evmc_opcode::OP_SWAP4:
                case evmc_opcode::OP_SWAP5:
                case evmc_opcode::OP_SWAP6:
                case evmc_opcode::OP_SWAP7:
                case evmc_opcode::OP_SWAP8:
                case evmc_opcode::OP_SWAP9:
                case evmc_opcode::OP_SWAP10:
                case evmc_opcode::OP_SWAP11:
                case evmc_opcode::OP_SWAP12:
                case evmc_opcode::OP_SWAP13:
                case evmc_opcode::OP_SWAP14:
                case evmc_opcode::OP_SWAP15:
                case evmc_opcode::OP_SWAP16:
                case evmc_opcode::OP_DUP1:
                case evmc_opcode::OP_DUP2:
                case evmc_opcode::OP_DUP3:
                case evmc_opcode::OP_DUP4:
                case evmc_opcode::OP_DUP5:
                case evmc_opcode::OP_DUP6:
                case evmc_opcode::OP_DUP7:
                case evmc_opcode::OP_DUP8:
                case evmc_opcode::OP_DUP9:
                case evmc_opcode::OP_DUP10:
                case evmc_opcode::OP_DUP11:
                case evmc_opcode::OP_DUP12:
                case evmc_opcode::OP_DUP13:
                case evmc_opcode::OP_DUP14:
                case evmc_opcode::OP_DUP15:
                case evmc_opcode::OP_DUP16:
                    break;
                case evmc_opcode::OP_CALLDATALOAD:
                case evmc_opcode::OP_SLOAD:
                case evmc_opcode::OP_MLOAD:
                case evmc_opcode::OP_CALLDATASIZE:
                case evmc_opcode::OP_LT:
                case evmc_opcode::OP_GT:
                case evmc_opcode::OP_DIV:
                case evmc_opcode::OP_SDIV:
                case evmc_opcode::OP_SAR:
                case evmc_opcode::OP_AND:
                case evmc_opcode::OP_EQ:
                case evmc_opcode::OP_CALLVALUE:
                case evmc_opcode::OP_ISZERO:
                case evmc_opcode::OP_ADD:
                case evmc_opcode::OP_EXP:
                case evmc_opcode::OP_CALLER:
                case evmc_opcode::OP_KECCAK256:
                case evmc_opcode::OP_SUB:
                case evmc_opcode::OP_ADDRESS:
                case evmc_opcode::OP_GAS:
                case evmc_opcode::OP_MUL:
                case evmc_opcode::OP_RETURNDATASIZE:
                case evmc_opcode::OP_NOT:
                case evmc_opcode::OP_SHR:
                case evmc_opcode::OP_SHL:
                case evmc_opcode::OP_EXTCODESIZE:
                case evmc_opcode::OP_SLT:
                case evmc_opcode::OP_OR:
                case evmc_opcode::OP_NUMBER:
                case evmc_opcode::OP_PC:
                case evmc_opcode::OP_TIMESTAMP:
                case evmc_opcode::OP_BALANCE:
                case evmc_opcode::OP_SELFBALANCE:
                case evmc_opcode::OP_MULMOD:
                case evmc_opcode::OP_ADDMOD:
                case evmc_opcode::OP_BASEFEE:
                case evmc_opcode::OP_BLOCKHASH:
                case evmc_opcode::OP_BYTE:
                case evmc_opcode::OP_XOR:
                case evmc_opcode::OP_ORIGIN:
                case evmc_opcode::OP_CODESIZE:
                case evmc_opcode::OP_MOD:
                case evmc_opcode::OP_SIGNEXTEND:
                case evmc_opcode::OP_GASLIMIT:
                case evmc_opcode::OP_PREVRANDAO:
                case evmc_opcode::OP_SGT:
                case evmc_opcode::OP_GASPRICE:
                case evmc_opcode::OP_MSIZE:
                case evmc_opcode::OP_EXTCODEHASH:
                case evmc_opcode::OP_STATICCALL:
                case evmc_opcode::OP_DELEGATECALL:
                case evmc_opcode::OP_CALL:
                case evmc_opcode::OP_CALLCODE:
                case evmc_opcode::OP_CREATE:
                case evmc_opcode::OP_CREATE2:
                case evmc_opcode::OP_COINBASE:
                case evmc_opcode::OP_CHAINID:
                case evmc_opcode::OP_SMOD:
                    copy_stack(op_code, top_stack, trace_stack);

                    CHECK(trace_stack.size() == 1);
                    CHECK(trace_stack[0] == "0x1f");
                    break;
                default:
                    copy_stack(op_code, top_stack, trace_stack);

                    CHECK(trace_stack.empty());
                    break;
            }
        }
    }
}

TEST_CASE("copy_memory") {
    evmone::Memory memory;
    for (std::uint8_t idx = 0; idx < 16; ++idx) {
        memory[idx] = idx;
    }

    SECTION("TRACE_MEMORY NOT SET") {
        std::optional<TraceMemory> trace_memory;
        copy_memory(memory, trace_memory);

        CHECK(trace_memory.has_value() == false);
    }
    SECTION("TRACE_MEMORY LEN == 0") {
        std::optional<TraceMemory> trace_memory = TraceMemory{0, 0};
        copy_memory(memory, trace_memory);

        CHECK(trace_memory.has_value() == false);
    }
    SECTION("TRACE_MEMORY LEN != 0") {
        std::optional<TraceMemory> trace_memory = TraceMemory{0, 10};
        copy_memory(memory, trace_memory);

        CHECK(trace_memory.has_value() == true);
        CHECK(nlohmann::json(trace_memory.value()) == R"({
            "off":0,
            "data":"0x00010203040506070809"
        })"_json);
    }
}

TEST_CASE("copy_store") {
    const size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    SECTION("op_code == OP_SSTORE") {
        std::optional<TraceStorage> trace_storage;
        copy_store(evmc_opcode::OP_SSTORE, top_stack, trace_storage);

        CHECK(trace_storage.has_value() == true);
        CHECK(nlohmann::json(trace_storage.value()) == R"({
            "key":"0x1f",
            "val":"0x1e"
        })"_json);
    }
    SECTION("op_code != OP_SSTORE") {
        std::optional<TraceStorage> trace_storage;
        copy_store(evmc_opcode::OP_CALLDATASIZE, top_stack, trace_storage);

        CHECK(trace_storage.has_value() == false);
    }
}

TEST_CASE("copy_memory_offset_len") {
    const size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    for (std::uint8_t op_code = evmc_opcode::OP_STOP; op_code < evmc_opcode::OP_SELFDESTRUCT; ++op_code) {
        std::optional<TraceMemory> trace_memory;
        copy_memory_offset_len(op_code, top_stack, trace_memory);

        switch (op_code) {
            case evmc_opcode::OP_MSTORE:
            case evmc_opcode::OP_MLOAD:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 31
                })"_json);
                break;
            case evmc_opcode::OP_MSTORE8:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 31
                })"_json);
                break;
            case evmc_opcode::OP_RETURNDATACOPY:
            case evmc_opcode::OP_CALLDATACOPY:
            case evmc_opcode::OP_CODECOPY:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 31
                })"_json);
                break;
            case evmc_opcode::OP_STATICCALL:
            case evmc_opcode::OP_DELEGATECALL:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 27
                })"_json);
                break;
            case evmc_opcode::OP_CALL:
            case evmc_opcode::OP_CALLCODE:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 26
                })"_json);
                break;
            case evmc_opcode::OP_CREATE:
            case evmc_opcode::OP_CREATE2:
                CHECK(trace_memory.has_value() == true);
                CHECK(nlohmann::json(trace_memory.value()) == R"({
                    "data":"",
                    "off": 0
                })"_json);
                break;
            default:
                CHECK(trace_memory.has_value() == false);
                break;
        }
    }
}

TEST_CASE("push_memory_offset_len") {
    const size_t stack_size{32};
    evmone::uint256 stack[stack_size] = {
        {0x00}, {0x01}, {0x02}, {0x03}, {0x04}, {0x05}, {0x06}, {0x07}, {0x08}, {0x09}, {0x0A}, {0x0B}, {0x0C}, {0x0D}, {0x0E}, {0x0F}, {0x10}, {0x11}, {0x12}, {0x13}, {0x14}, {0x15}, {0x16}, {0x17}, {0x18}, {0x19}, {0x1A}, {0x1B}, {0x1C}, {0x1D}, {0x1E}, {0x1F}};
    evmone::uint256* top_stack = &stack[stack_size - 1];

    for (std::uint8_t op_code = evmc_opcode::OP_STOP; op_code < evmc_opcode::OP_SELFDESTRUCT; ++op_code) {
        std::stack<TraceMemory> tms;
        push_memory_offset_len(op_code, top_stack, tms);

        switch (op_code) {
            case evmc_opcode::OP_STATICCALL:
            case evmc_opcode::OP_DELEGATECALL:
                CHECK(tms.size() == 1);
                CHECK(nlohmann::json(tms.top()) == R"({
                    "data":"",
                    "off": 27
                })"_json);
                break;
            case evmc_opcode::OP_CALL:
            case evmc_opcode::OP_CALLCODE:
                CHECK(tms.size() == 1);
                CHECK(nlohmann::json(tms.top()) == R"({
                    "data":"",
                    "off": 26
                })"_json);
                break;
            case evmc_opcode::OP_CREATE:
            case evmc_opcode::OP_CREATE2:
                CHECK(tms.size() == 1);
                CHECK(nlohmann::json(tms.top()) == R"({
                    "data":"",
                    "off": 0
                })"_json);
                break;
            default:
                CHECK(tms.empty());
                break;
        }
    }
}

TEST_CASE("to_string") {
    SECTION("value == 0") {
        auto out = to_string(intx::uint256{0});
        CHECK(out == "0x0000000000000000000000000000000000000000000000000000000000000000");
    }
    SECTION("value == 1") {
        auto out = to_string(intx::uint256{1});
        CHECK(out == "0x0000000000000000000000000000000000000000000000000000000000000001");
    }
    SECTION("value == 1") {
        auto out = to_string(intx::uint256{0xdeadbeaf});
        CHECK(out == "0x00000000000000000000000000000000000000000000000000000000deadbeaf");
    }
}

TEST_CASE("TraceConfig") {
    SECTION("dump on stream") {
        TraceConfig config{true, false, true};

        std::ostringstream os;
        os << config;
        CHECK(os.str() == "vmTrace: true Trace: false stateDiff: true");
    }
    SECTION("json deserialization: empty") {
        nlohmann::json json = R"([])"_json;

        TraceConfig config;
        from_json(json, config);

        CHECK(config.trace == false);
        CHECK(config.vm_trace == false);
        CHECK(config.state_diff == false);
    }
    SECTION("json deserialization: full") {
        nlohmann::json json = R"(["trace", "vmTrace", "stateDiff"])"_json;

        TraceConfig config;
        from_json(json, config);

        CHECK(config.trace == true);
        CHECK(config.vm_trace == true);
        CHECK(config.state_diff == true);
    }
}

TEST_CASE("TraceFilter") {
    SECTION("dump on stream: simple") {
        TraceFilter config;

        std::ostringstream os;
        os << config;

        CHECK(os.str() == "from_block: 0x0, to_block: latest, after: 0, count: 4294967295");
    }
    SECTION("dump on stream: full") {
        TraceFilter config;
        config.from_addresses.push_back(0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030_address);
        config.to_addresses.push_back(0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7031_address);
        config.mode = "union";
        std::ostringstream os;
        os << config;

        CHECK(os.str() ==
              "from_block: 0x0, to_block: latest, from_addresses: [0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7030, ], "
              "to_addresses: [0x0a6bb546b9208cfab9e8fa2b9b2c042b18df7031, ], mode: union, after: 0, count: 4294967295");
    }
    SECTION("json deserialization: simple") {
        nlohmann::json json = R"({
          "after": 18,
          "count": 10,
          "fromBlock": "0x6DDD00",
          "toBlock": "latest"
        })"_json;

        TraceFilter config = json;

        CHECK(config.after == 18);
        CHECK(config.count == 10);
        CHECK(config.from_block.is_number() == true);
        CHECK(config.from_block.number() == 0x6DDD00);
        CHECK(config.to_block.is_tag() == true);
        CHECK(config.to_block.tag() == "latest");
        CHECK(config.from_addresses.empty());
        CHECK(config.to_addresses.empty());
        CHECK(!config.mode);
    }
    SECTION("json deserialization: full") {
        nlohmann::json json = R"({
          "after": 18,
          "count": 10,
          "fromAddress": [
            "0xd05526a73bf45dadf7f9a99dcceac23c2d43c6c7"
          ],
          "fromBlock": "0x6DDD00",
          "toAddress": [
            "0x11fe4b6ae13d2a6055c8d9cf65c55bac32b5d844"
          ],
          "toBlock": "latest",
          "mode": "union"
        })"_json;

        TraceFilter config;
        from_json(json, config);

        CHECK(config.after == 18);
        CHECK(config.count == 10);
        CHECK(config.from_block.is_number() == true);
        CHECK(config.from_block.number() == 0x6DDD00);
        CHECK(config.to_block.is_tag() == true);
        CHECK(config.from_addresses.size() == 1);
        CHECK(config.from_addresses[0] == 0xd05526a73bf45dadf7f9a99dcceac23c2d43c6c7_address);
        CHECK(config.to_addresses.size() == 1);
        CHECK(config.to_addresses[0] == 0x11fe4b6ae13d2a6055c8d9cf65c55bac32b5d844_address);
        CHECK(config.mode);
        CHECK(config.mode.value() == "union");
    }
}

TEST_CASE("TraceCall") {
    SECTION("json deserialization") {
        nlohmann::json json = R"([
            {
                "from": "0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9",
                "to": "0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa",
                "gas": "0x7530",
                "gasPrice": "0x3b9aca00",
                "value": "0x2FAF080",
                "data": "0x01"
            },
            ["trace", "vmTrace", "stateDiff"]
       ])"_json;

        TraceCall trace_call;
        from_json(json, trace_call);

        CHECK(trace_call.call.from == 0x8ced5ad0d8da4ec211c17355ed3dbfec4cf0e5b9_address);
        CHECK(trace_call.call.to == 0x5e1f0c9ddbe3cb57b80c933fab5151627d7966fa_address);
        CHECK(trace_call.call.gas == 0x7530);
        CHECK(trace_call.call.gas_price == 0x3b9aca00);
        CHECK(trace_call.call.value == 0x2FAF080);
        CHECK(trace_call.call.data == *silkworm::from_hex("01"));

        CHECK(trace_call.trace_config.trace == true);
        CHECK(trace_call.trace_config.vm_trace == true);
        CHECK(trace_call.trace_config.state_diff == true);
    }
}

TEST_CASE("TraceCallTraces: json serialization") {
    TraceCallTraces tct;
    tct.output = "0xdeadbeaf";

    SECTION("with transaction_hash") {
        tct.transaction_hash = 0xe0d4933284f1254835aac8823535278f0eb9608b137266cf3d3d8df8240bbe48_bytes32;
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": null,
            "trace": [],
            "transactionHash": "0xe0d4933284f1254835aac8823535278f0eb9608b137266cf3d3d8df8240bbe48",
            "vmTrace": null
        })"_json);
    }

    SECTION("with state_diff") {
        tct.state_diff = StateDiff{};
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": {},
            "trace": [],
            "vmTrace": null
        })"_json);
    }

    SECTION("with trace") {
        tct.trace.push_back(Trace{});
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": null,
            "trace": [
                {
                "action": {
                    "from": "0x0000000000000000000000000000000000000000",
                    "gas": "0x0",
                    "value": "0x0"
                },
                "result": null,
                "subtraces": 0,
                "traceAddress": [],
                "type": ""
                }
            ],
            "vmTrace": null
        })"_json);
    }

    SECTION("with vm_trace") {
        tct.vm_trace = VmTrace{};
        CHECK(nlohmann::json(tct) == R"({
            "output": "0xdeadbeaf",
            "stateDiff": null,
            "trace": [],
            "vmTrace": {
                "code": "0x",
                "ops": []
            }
        })"_json);
    }
}

TEST_CASE("TraceCallResult: json serialization") {
    TraceCallResult tcr;

    SECTION("with traces") {
        tcr.traces = TraceCallTraces{};
        CHECK(nlohmann::json(tcr) == R"({
            "output": "0x",
            "stateDiff": null,
            "trace": [],
            "vmTrace": null
        })"_json);
    }
}

TEST_CASE("TraceManyCallResult: json serialization") {
    TraceManyCallResult tmcr;

    SECTION("with traces") {
        tmcr.traces.push_back(TraceCallTraces{});
        CHECK(nlohmann::json(tmcr) == R"([
            {
                "output": "0x",
                "stateDiff": null,
                "trace": [],
                "vmTrace": null
            }
        ])"_json);
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::trace
