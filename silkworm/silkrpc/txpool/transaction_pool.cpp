/*
    Copyright 2020-2022 The Silkrpc Authors

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

#include <boost/endian/conversion.hpp>

#include <silkworm/silkrpc/common/clock_time.hpp>
#include <silkworm/silkrpc/grpc/unary_rpc.hpp>

namespace silkrpc::txpool {

TransactionPool::TransactionPool(boost::asio::io_context& context, std::shared_ptr<grpc::Channel> channel, agrpc::GrpcContext& grpc_context)
    : TransactionPool(context.get_executor(), ::txpool::Txpool::NewStub(channel, grpc::StubOptions()), grpc_context) {}

TransactionPool::TransactionPool(boost::asio::io_context::executor_type executor, std::unique_ptr<::txpool::Txpool::StubInterface> stub, agrpc::GrpcContext& grpc_context)
    : executor_(executor), stub_(std::move(stub)), grpc_context_(grpc_context) {
    SILKRPC_TRACE << "TransactionPool::ctor " << this << "\n";
}

TransactionPool::~TransactionPool() {
    SILKRPC_TRACE << "TransactionPool::dtor " << this << "\n";
}

boost::asio::awaitable<OperationResult> TransactionPool::add_transaction(const silkworm::ByteView& rlp_tx) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "TransactionPool::add_transaction rlp_tx=" << silkworm::to_hex(rlp_tx) << "\n";
    ::txpool::AddRequest request;
    request.add_rlptxs(rlp_tx.data(), rlp_tx.size());
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncAdd> add_transaction_rpc{*stub_, grpc_context_};
    const auto reply = co_await add_transaction_rpc.finish_on(executor_, request);
    const auto imported_size = reply.imported_size();
    const auto errors_size = reply.errors_size();
    SILKRPC_DEBUG << "TransactionPool::add_transaction imported_size=" << imported_size << " errors_size=" << errors_size << "\n";
    OperationResult result;
    if (imported_size == 1) {
        const auto import_result = reply.imported(0);
        SILKRPC_DEBUG << "TransactionPool::add_transaction import_result=" << import_result << "\n";
        if (import_result != ::txpool::ImportResult::SUCCESS) {
            result.success = false;
            if (errors_size >= 1) {
                const auto import_error = reply.errors(0);
                result.error_descr = import_error;
                SILKRPC_WARN << "TransactionPool::add_transaction import_result=" << import_result << " error=" << import_error << "\n";
            } else {
                result.error_descr = "no specific error";
                SILKRPC_WARN << "TransactionPool::add_transaction import_result=" << import_result << ", no error received\n";
            }
        } else {
            result.success = true;
        }
    } else {
        result.success = false;
        result.error_descr = "unexpected imported size";
        SILKRPC_WARN << "TransactionPool::add_transaction unexpected imported_size=" << imported_size << "\n";
    }
    SILKRPC_DEBUG << "TransactionPool::add_transaction t=" << clock_time::since(start_time) << "\n";
    co_return result;
}

boost::asio::awaitable<std::optional<silkworm::Bytes>> TransactionPool::get_transaction(const evmc::bytes32& tx_hash) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "TransactionPool::get_transaction tx_hash=" << tx_hash << "\n";
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
    const auto rlptxs_size = reply.rlptxs_size();
    SILKRPC_DEBUG << "TransactionPool::get_transaction rlptxs_size=" << rlptxs_size << "\n";
    if (rlptxs_size == 1) {
        const auto rlptx = reply.rlptxs(0);
        SILKRPC_DEBUG << "TransactionPool::get_transaction t=" << clock_time::since(start_time) << "\n";
        co_return silkworm::Bytes{rlptx.begin(), rlptx.end()};
    } else {
        SILKRPC_WARN << "TransactionPool::get_transaction unexpected rlptxs_size=" << rlptxs_size << "\n";
        SILKRPC_DEBUG << "TransactionPool::get_transaction t=" << clock_time::since(start_time) << "\n";
        co_return std::nullopt;
    }
}

boost::asio::awaitable<std::optional<uint64_t>> TransactionPool::nonce(const evmc::address& address) {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "TransactionPool::nonce address=" << address << "\n";
    ::txpool::NonceRequest request;
    request.set_allocated_address(H160_from_address(address));
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncNonce> nonce_rpc{*stub_, grpc_context_};
    const auto reply = co_await nonce_rpc.finish_on(executor_, request);
    SILKRPC_DEBUG << "TransactionPool::nonce found:" << reply.found() << " nonce: " << reply.nonce() <<
                        " t=" << clock_time::since(start_time) << "\n";
    co_return reply.found() ? std::optional<uint64_t>{reply.nonce()} : std::nullopt;
}

boost::asio::awaitable<StatusInfo> TransactionPool::get_status() {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "TransactionPool::get_status\n";
    ::txpool::StatusRequest request;
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncStatus> status_rpc{*stub_, grpc_context_};
    const auto reply = co_await status_rpc.finish_on(executor_, request);
    StatusInfo status_info{
        .queued_count = reply.queuedcount(),
        .pending_count = reply.pendingcount(),
        .base_fee_count = reply.basefeecount()
    };
    SILKRPC_DEBUG << "TransactionPool::get_status t=" << clock_time::since(start_time) << "\n";
    co_return status_info;
}

boost::asio::awaitable<TransactionsInPool> TransactionPool::get_transactions() {
    const auto start_time = clock_time::now();
    SILKRPC_DEBUG << "TransactionPool::get_transactions\n";
    ::txpool::AllRequest request;
    UnaryRpc<&::txpool::Txpool::StubInterface::AsyncAll> all_rpc{*stub_, grpc_context_};
    const auto reply = co_await all_rpc.finish_on(executor_, request);
    TransactionsInPool transactions_in_pool;
    const auto txs_size = reply.txs_size();
    for (int i = 0; i < txs_size; i++) {
        const auto tx = reply.txs(i);
        TransactionInfo element{};
        element.sender = address_from_H160(tx.sender());
        const auto rlp = tx.rlptx();
        element.rlp = silkworm::Bytes{rlp.begin(), rlp.end()};
        if (tx.txntype() == ::txpool::AllReply_TxnType_PENDING) {
            element.transaction_type = PENDING;
        } else if (tx.txntype() == ::txpool::AllReply_TxnType_QUEUED) {
            element.transaction_type = QUEUED;
        } else {
            element.transaction_type = BASE_FEE;
        }
        transactions_in_pool.push_back(element);
    }
    SILKRPC_DEBUG << "TransactionPool::get_transactions t=" << clock_time::since(start_time) << "\n";
    co_return transactions_in_pool;
}

evmc::address TransactionPool::address_from_H160(const types::H160& h160) {
    uint64_t hi_hi = h160.hi().hi();
    uint64_t hi_lo = h160.hi().lo();
    uint32_t lo = h160.lo();
    evmc::address address{};
    boost::endian::store_big_u64(address.bytes +  0, hi_hi);
    boost::endian::store_big_u64(address.bytes +  8, hi_lo);
    boost::endian::store_big_u32(address.bytes + 16, lo);
    return address;
}

types::H160* TransactionPool::H160_from_address(const evmc::address& address) {
    auto h160{new types::H160()};
    auto hi{H128_from_bytes(address.bytes)};
    h160->set_allocated_hi(hi);
    h160->set_lo(boost::endian::load_big_u32(address.bytes + 16));
    return h160;
}

types::H128* TransactionPool::H128_from_bytes(const uint8_t* bytes) {
    auto h128{new types::H128()};
    h128->set_hi(boost::endian::load_big_u64(bytes));
    h128->set_lo(boost::endian::load_big_u64(bytes + 8));
    return h128;
}

} // namespace silkrpc::txpool
