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

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/rpc/common/clock_time.hpp>
#include <silkworm/rpc/grpc/unary_rpc.hpp>

namespace silkworm::rpc::txpool {

TransactionPool::TransactionPool(boost::asio::io_context& context, const std::shared_ptr<grpc::Channel>& channel,
                                 agrpc::GrpcContext& grpc_context)
    : TransactionPool(context.get_executor(), ::txpool::Txpool::NewStub(channel, grpc::StubOptions()), grpc_context) {}

TransactionPool::TransactionPool(boost::asio::io_context::executor_type executor,
                                 std::unique_ptr<::txpool::Txpool::StubInterface> stub,
                                 agrpc::GrpcContext& grpc_context)
    : executor_(std::move(executor)), stub_(std::move(stub)), grpc_context_(grpc_context) {
    SILK_TRACE << "TransactionPool::ctor " << this;
}

TransactionPool::~TransactionPool() {
    SILK_TRACE << "TransactionPool::dtor " << this;
}

Task<OperationResult> TransactionPool::add_transaction(const silkworm::ByteView& rlp_tx) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "TransactionPool::add_transaction rlp_tx=" << silkworm::to_hex(rlp_tx);
    ::txpool::AddRequest request;
    request.add_rlp_txs(rlp_tx.data(), rlp_tx.size());
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncAdd> add_transaction_rpc{*stub_, grpc_context_};
    const auto reply = co_await add_transaction_rpc.finish_on(executor_, request);
    const auto imported_size = reply.imported_size();
    const auto errors_size = reply.errors_size();
    SILK_DEBUG << "TransactionPool::add_transaction imported_size=" << imported_size << " errors_size=" << errors_size;
    OperationResult result;
    if (imported_size == 1) {
        const auto import_result = reply.imported(0);
        SILK_DEBUG << "TransactionPool::add_transaction import_result=" << import_result;
        if (import_result != ::txpool::ImportResult::SUCCESS) {
            result.success = false;
            if (errors_size >= 1) {
                const auto& import_error = reply.errors(0);
                result.error_descr = import_error;
                SILK_WARN << "TransactionPool::add_transaction import_result=" << import_result << " error=" << import_error;
            } else {
                result.error_descr = "no specific error";
                SILK_WARN << "TransactionPool::add_transaction import_result=" << import_result << ", no error received";
            }
        } else {
            result.success = true;
        }
    } else {
        result.success = false;
        result.error_descr = "unexpected imported size";
        SILK_WARN << "TransactionPool::add_transaction unexpected imported_size=" << imported_size;
    }
    SILK_DEBUG << "TransactionPool::add_transaction t=" << clock_time::since(start_time);
    co_return result;
}

Task<std::optional<silkworm::Bytes>> TransactionPool::get_transaction(const evmc::bytes32& tx_hash) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "TransactionPool::get_transaction tx_hash=" << silkworm::to_hex(tx_hash);
    auto hi = new ::types::H128{};
    auto lo = new ::types::H128{};
    hi->set_hi(evmc::load64be(tx_hash.bytes + 0));
    hi->set_lo(evmc::load64be(tx_hash.bytes + 8));
    lo->set_hi(evmc::load64be(tx_hash.bytes + 16));
    lo->set_lo(evmc::load64be(tx_hash.bytes + 24));
    ::txpool::TransactionsRequest request;
    ::types::H256* hash_h256{request.add_hashes()};
    hash_h256->set_allocated_hi(hi);  // take ownership
    hash_h256->set_allocated_lo(lo);  // take ownership
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncTransactions> get_transactions_rpc{*stub_, grpc_context_};
    const auto reply = co_await get_transactions_rpc.finish_on(executor_, request);
    const auto rlp_txs_size = reply.rlp_txs_size();
    SILK_DEBUG << "TransactionPool::get_transaction rlp_txs_size=" << rlp_txs_size;
    if (rlp_txs_size == 1) {
        const auto& rlp_tx = reply.rlp_txs(0);
        SILK_DEBUG << "TransactionPool::get_transaction t=" << clock_time::since(start_time);
        co_return silkworm::Bytes{rlp_tx.begin(), rlp_tx.end()};
    } else {
        SILK_WARN << "TransactionPool::get_transaction unexpected rlp_txs_size=" << rlp_txs_size;
        SILK_DEBUG << "TransactionPool::get_transaction t=" << clock_time::since(start_time);
        co_return std::nullopt;
    }
}

Task<std::optional<uint64_t>> TransactionPool::nonce(const evmc::address& address) {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "TransactionPool::nonce address=" << address;
    ::txpool::NonceRequest request;
    request.set_allocated_address(H160_from_address(address).release());
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncNonce> nonce_rpc{*stub_, grpc_context_};
    const auto reply = co_await nonce_rpc.finish_on(executor_, request);
    SILK_DEBUG << "TransactionPool::nonce found:" << reply.found() << " nonce: " << reply.nonce() << " t=" << clock_time::since(start_time);
    co_return reply.found() ? std::optional<uint64_t>{reply.nonce()} : std::nullopt;
}

Task<StatusInfo> TransactionPool::get_status() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "TransactionPool::get_status";
    ::txpool::StatusRequest request;
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncStatus> status_rpc{*stub_, grpc_context_};
    const auto reply = co_await status_rpc.finish_on(executor_, request);
    StatusInfo status_info{
        .queued_count = reply.queued_count(),
        .pending_count = reply.pending_count(),
        .base_fee_count = reply.base_fee_count()};
    SILK_DEBUG << "TransactionPool::get_status t=" << clock_time::since(start_time);
    co_return status_info;
}

Task<TransactionsInPool> TransactionPool::get_transactions() {
    const auto start_time = clock_time::now();
    SILK_DEBUG << "TransactionPool::get_transactions";
    ::txpool::AllRequest request;
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncAll> all_rpc{*stub_, grpc_context_};
    const auto reply = co_await all_rpc.finish_on(executor_, request);
    TransactionsInPool transactions_in_pool;
    const auto txs_size = reply.txs_size();
    for (int i = 0; i < txs_size; i++) {
        const auto tx = reply.txs(i);
        TransactionInfo element{};
        element.sender = address_from_H160(tx.sender());
        const auto rlp = tx.rlp_tx();
        element.rlp = silkworm::Bytes{rlp.begin(), rlp.end()};
        if (tx.txn_type() == ::txpool::AllReply_TxnType_PENDING) {
            element.transaction_type = PENDING;
        } else if (tx.txn_type() == ::txpool::AllReply_TxnType_QUEUED) {
            element.transaction_type = QUEUED;
        } else {
            element.transaction_type = BASE_FEE;
        }
        transactions_in_pool.push_back(element);
    }
    SILK_DEBUG << "TransactionPool::get_transactions t=" << clock_time::since(start_time);
    co_return transactions_in_pool;
}

}  // namespace silkworm::rpc::txpool
