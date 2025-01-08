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

#include "transaction_pool.hpp"

#include <string>
#include <utility>

#include <agrpc/test.hpp>
#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>
#include <gmock/gmock.h>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/test_util/grpc_actions.hpp>
#include <silkworm/infra/grpc/test_util/grpc_responder.hpp>
#include <silkworm/infra/grpc/test_util/interfaces/txpool_mock_fix24351.grpc.pb.h>
#include <silkworm/interfaces/txpool/txpool.grpc.pb.h>
#include <silkworm/rpc/test_util/api_test_base.hpp>

namespace grpc {

inline bool operator==(const Status& lhs, const Status& rhs) {
    return lhs.error_code() == rhs.error_code() &&
           lhs.error_message() == rhs.error_message() &&
           lhs.error_details() == rhs.error_details();
}

::types::H160* make_h160(uint64_t hi_hi, uint64_t hi_lo, uint32_t lo) {
    auto h128_ptr{new ::types::H128()};
    h128_ptr->set_hi(hi_hi);
    h128_ptr->set_lo(hi_lo);
    auto h160_ptr{new ::types::H160()};
    h160_ptr->set_allocated_hi(h128_ptr);
    h160_ptr->set_lo(lo);
    return h160_ptr;
}
}  // namespace grpc

namespace txpool {

inline bool operator==(const AddReply& lhs, const AddReply& rhs) {
    if (lhs.imported_size() != rhs.imported_size()) return false;
    for (auto i{0}; i < lhs.imported_size(); ++i) {
        if (lhs.imported(i) != rhs.imported(i)) return false;
    }
    if (lhs.errors_size() != rhs.errors_size()) return false;
    for (auto i{0}; i < lhs.errors_size(); ++i) {
        if (lhs.errors(i) != rhs.errors(i)) return false;
    }
    return true;
}
}  // namespace txpool

namespace silkworm::rpc::txpool {

using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;
using StrictMockTxpoolStub = testing::StrictMock<::txpool::MockTxpoolStub>;

using TransactionPoolTest = test_util::GrpcApiTestBase<TransactionPool, StrictMockTxpoolStub>;

#ifndef SILKWORM_SANITIZE
TEST_CASE_METHOD(TransactionPoolTest, "TransactionPool::add_transaction", "[rpc][txpool][transaction_pool]") {
    test::StrictMockAsyncResponseReader<::txpool::AddReply> reader;
    EXPECT_CALL(*stub_, AsyncAddRaw).WillOnce(testing::Return(&reader));
    const Bytes tx_rlp{0x00, 0x01};

    SECTION("call add_transaction and check import success") {
        ::txpool::AddReply response;
        response.add_imported(::txpool::ImportResult::SUCCESS);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto result = run<&TransactionPool::add_transaction>(tx_rlp);
        CHECK(result.success);
    }

    SECTION("call add_transaction and check import failure [unexpected import size]") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto result = run<&TransactionPool::add_transaction>(tx_rlp);
        CHECK(!result.success);
    }

    SECTION("call add_transaction and check import failure [invalid error]") {
        ::txpool::AddReply response;
        response.add_imported(::txpool::ImportResult::INVALID);
        response.add_errors("invalid transaction");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto result = run<&TransactionPool::add_transaction>(tx_rlp);
        CHECK(!result.success);
    }

    SECTION("call add_transaction and check import failure [internal error]") {
        ::txpool::AddReply response;
        response.add_imported(::txpool::ImportResult::INTERNAL_ERROR);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto result = run<&TransactionPool::add_transaction>(tx_rlp);
        CHECK(!result.success);
    }

    SECTION("call add_transaction and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&TransactionPool::add_transaction>(tx_rlp)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(TransactionPoolTest, "TransactionPool::get_transaction", "[rpc][txpool][transaction_pool]") {
    test::StrictMockAsyncResponseReader<::txpool::TransactionsReply> reader;
    EXPECT_CALL(*stub_, AsyncTransactionsRaw).WillOnce(testing::Return(&reader));
    const evmc::bytes32 tx_hash{0x3763e4f6e4198413383534c763f3f5dac5c5e939f0a81724e3beb96d6e2ad0d5_bytes32};

    SECTION("call get_transaction and check success") {
        ::txpool::TransactionsReply response;
        response.add_rlp_txs("0804");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto tx_rlp = run<&TransactionPool::get_transaction>(tx_hash);
        CHECK(tx_rlp);
        if (tx_rlp) {
            CHECK(tx_rlp.value() == Bytes{0x30, 0x38, 0x30, 0x34});
        }
    }

    SECTION("call get_transaction and check result is null [rlp_txs size is 0]") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto tx_rlp = run<&TransactionPool::get_transaction>(tx_hash);
        CHECK(!tx_rlp);
    }

    SECTION("call get_transaction and check result is null [rlp_txs size is greater than 1]") {
        ::txpool::TransactionsReply response;
        response.add_rlp_txs("0804");
        response.add_rlp_txs("0905");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto tx_rlp = run<&TransactionPool::get_transaction>(tx_hash);
        CHECK(!tx_rlp);
    }

    SECTION("call get_transaction and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&TransactionPool::get_transaction>(tx_hash)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(TransactionPoolTest, "TransactionPool::nonce", "[rpc][txpool][transaction_pool]") {
    test::StrictMockAsyncResponseReader<::txpool::NonceReply> reader;
    EXPECT_CALL(*stub_, AsyncNonceRaw).WillOnce(testing::Return(&reader));
    const evmc::address account{0x99f9b87991262f6ba471f09758cde1c0fc1de734_address};

    SECTION("call nonce and check success") {
        ::txpool::NonceReply response;
        response.set_found(true);
        response.set_nonce(21);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto nonce = run<&TransactionPool::nonce>(account);
        CHECK(nonce);
        if (nonce) {
            CHECK(nonce.value() == 21);
        }
    }

    SECTION("call nonce and check result is null") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto nonce = run<&TransactionPool::nonce>(account);
        CHECK(!nonce);
    }

    SECTION("call nonce and check result is null [not found]") {
        ::txpool::NonceReply response;
        response.set_found(false);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto nonce = run<&TransactionPool::nonce>(account);
        CHECK(!nonce);
    }

    SECTION("call nonce and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&TransactionPool::nonce>(account)), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(TransactionPoolTest, "TransactionPool::get_status", "[rpc][txpool][transaction_pool]") {
    test::StrictMockAsyncResponseReader<::txpool::StatusReply> reader;
    EXPECT_CALL(*stub_, AsyncStatusRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_status and check success") {
        ::txpool::StatusReply response;
        response.set_queued_count(0x6);
        response.set_pending_count(0x5);
        response.set_base_fee_count(0x4);
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto status_info = run<&TransactionPool::get_status>();
        CHECK(status_info.queued_count == 0x6);
        CHECK(status_info.pending_count == 0x5);
        CHECK(status_info.base_fee_count == 0x4);
    }

    SECTION("call get_status and check result is empty") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto status_info = run<&TransactionPool::get_status>();
        CHECK(status_info.queued_count == 0);
        CHECK(status_info.pending_count == 0);
        CHECK(status_info.base_fee_count == 0);
    }

    SECTION("call get_status and get error") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_cancelled(grpc_context_));
        CHECK_THROWS_AS((run<&TransactionPool::get_status>()), rpc::GrpcStatusError);
    }
}

TEST_CASE_METHOD(TransactionPoolTest, "TransactionPool::get_transactions", "[rpc][txpool][transaction_pool]") {
    test::StrictMockAsyncResponseReader<::txpool::AllReply> reader;
    EXPECT_CALL(*stub_, AsyncAllRaw).WillOnce(testing::Return(&reader));

    SECTION("call get_transactions and check success [one tx]") {
        ::txpool::AllReply response;
        auto tx = response.add_txs();
        tx->set_txn_type(::txpool::AllReply_TxnType_QUEUED);
        auto address{grpc::make_h160(0xAAAAEEFFFFEEAAAA, 0x11DDBBAAAABBDD11, 0xCCDDDDCC)};
        tx->set_allocated_sender(address);
        tx->set_rlp_tx("0804");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto transactions = run<&TransactionPool::get_transactions>();
        REQUIRE(transactions.size() == 1);
        CHECK(transactions[0].transaction_type == TransactionType::kQueued);
        CHECK(transactions[0].sender == 0xaaaaeeffffeeaaaa11ddbbaaaabbdd11ccddddcc_address);
        CHECK(transactions[0].rlp == Bytes{0x30, 0x38, 0x30, 0x34});
    }

    SECTION("call get_transactions and check success [more than one tx]") {
        ::txpool::AllReply response;
        auto tx = response.add_txs();
        tx->set_txn_type(::txpool::AllReply_TxnType_QUEUED);
        auto address{grpc::make_h160(0xAAAAEEFFFFEEAAAA, 0x11DDBBAAAABBDD11, 0xCCDDDDCC)};
        tx->set_allocated_sender(address);
        tx->set_rlp_tx("0804");
        tx = response.add_txs();
        tx->set_txn_type(::txpool::AllReply_TxnType_PENDING);
        auto address1{grpc::make_h160(0xAAAAEEFFFFEEAAAA, 0x11DDBBAAAABBDD11, 0xCCDDDDDD)};
        tx->set_allocated_sender(address1);
        tx->set_rlp_tx("0806");
        tx = response.add_txs();
        tx->set_txn_type(::txpool::AllReply_TxnType_BASE_FEE);
        auto address2{grpc::make_h160(0xAAAAEEFFFFEEAAAA, 0x11DDBBAAAABBDD11, 0xCCDDDDEE)};
        tx->set_allocated_sender(address2);
        tx->set_rlp_tx("0807");
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_with(grpc_context_, std::move(response)));
        const auto transactions = run<&TransactionPool::get_transactions>();
        REQUIRE(transactions.size() == 3);
        CHECK(transactions[0].transaction_type == txpool::TransactionType::kQueued);
        CHECK(transactions[0].sender == 0xaaaaeeffffeeaaaa11ddbbaaaabbdd11ccddddcc_address);
        CHECK(transactions[0].rlp == Bytes{0x30, 0x38, 0x30, 0x34});
        CHECK(transactions[1].transaction_type == txpool::TransactionType::kPending);
        CHECK(transactions[1].sender == 0xaaaaeeffffeeaaaa11ddbbaaaabbdd11ccdddddd_address);
        CHECK(transactions[1].rlp == Bytes{0x30, 0x38, 0x30, 0x36});
        CHECK(transactions[2].transaction_type == txpool::TransactionType::kBaseFee);
        CHECK(transactions[2].sender == 0xaaaaeeffffeeaaaa11ddbbaaaabbdd11ccddddee_address);
        CHECK(transactions[2].rlp == Bytes{0x30, 0x38, 0x30, 0x37});
    }

    SECTION("call get_transactions and check result is empty") {
        EXPECT_CALL(reader, Finish).WillOnce(test::finish_ok(grpc_context_));
        const auto transactions = run<&TransactionPool::get_transactions>();
        CHECK(transactions.empty());
    }
}
#endif  // SILKWORM_SANITIZE

}  // namespace silkworm::rpc::txpool
