/*
   Copyright 2022 The Silkworm Authors

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

#include "remote_client.hpp"

#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/interfaces/execution/execution.grpc.pb.h>
#include <silkworm/node/common/log.hpp>
#include <silkworm/node/rpc/client/call.hpp>
#include <silkworm/node/rpc/common/conversion.hpp>

namespace silkworm::execution {

using namespace std::chrono;
using namespace boost::asio;

static void fill_header(const BlockHeader& bh, ::execution::Header* header) {
    header->set_allocated_parenthash(rpc::H256_from_bytes32(bh.parent_hash).release());
    header->set_allocated_coinbase(rpc::H160_from_address(bh.beneficiary).release());
    header->set_allocated_stateroot(rpc::H256_from_bytes32(bh.state_root).release());
    header->set_allocated_receiptroot(rpc::H256_from_bytes32(bh.receipts_root).release());
    header->set_allocated_logsbloom(rpc::H2048_from_string(to_string(bh.logs_bloom)).release());
    header->set_allocated_mixdigest(rpc::H256_from_bytes32(bh.mix_hash).release());
    header->set_blocknumber(bh.number);
    header->set_gaslimit(bh.gas_limit);
    header->set_gasused(bh.gas_used);
    header->set_timestamp(bh.timestamp);
    header->set_nonce(endian::load_big_u64(bh.nonce.data()));
    header->set_extradata(bh.extra_data.data(), bh.extra_data.size());
    header->set_allocated_difficulty(rpc::H256_from_uint256(bh.difficulty).release());
    header->set_allocated_blockhash(rpc::H256_from_bytes32(bh.hash()).release());
    header->set_allocated_ommerhash(rpc::H256_from_bytes32(bh.ommers_hash).release());
    header->set_allocated_transactionhash(rpc::H256_from_bytes32(bh.transactions_root).release());
    if (bh.base_fee_per_gas) {
        header->set_allocated_basefeepergas(rpc::H256_from_uint256(*bh.base_fee_per_gas).release());
    }
    if (bh.withdrawals_root) {
        header->set_allocated_withdrawalhash(rpc::H256_from_bytes32(*bh.withdrawals_root).release());
    }
}

RemoteClient::RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel)
    : grpc_context_(grpc_context), stub_(::execution::Execution::NewStub(channel)) {}

awaitable<void> RemoteClient::start() {
    throw std::runtime_error{"RemoteClient::start not implemented"};
}

awaitable<void> RemoteClient::insert_headers(const BlockVector& blocks) {
    ::execution::InsertHeadersRequest request;
    for (const auto& b : blocks) {
        ::execution::Header* header = request.add_headers();
        fill_header(b.header, header);
    }
    ::execution::EmptyMessage response;
    const auto grpc_status = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncInsertHeaders, stub_, request, response, grpc_context_);
    if (!grpc_status.ok()) {
        log::Error() << "RemoteClient::insert_headers error: " << grpc_status.error_message();
    }
}

awaitable<void> RemoteClient::insert_bodies(const BlockVector& blocks) {
    ::execution::InsertBodiesRequest request;
    for (const auto& b : blocks) {
        ::execution::BlockBody* body = request.add_bodies();
        body->set_allocated_blockhash(rpc::H256_from_bytes32(b.header.hash()).release());
        body->set_blocknumber(b.header.number);
        for (const auto& transaction : b.transactions) {
            Bytes tx_rlp;
            rlp::encode(tx_rlp, transaction);
            body->add_transactions(tx_rlp.data(), tx_rlp.size());
        }
        for (const auto& ommer : b.ommers) {
            ::execution::Header* uncle = body->add_uncles();
            fill_header(ommer, uncle);
        }
        if (b.withdrawals) {
            for (const auto& withdrawal : *b.withdrawals) {
                ::types::Withdrawal* w = body->add_withdrawals();
                w->set_index(withdrawal.index);
                w->set_validatorindex(withdrawal.validator_index);
                w->set_allocated_address(rpc::H160_from_address(withdrawal.address).release());
                w->set_allocated_amount(rpc::H256_from_uint256(withdrawal.amount).release());
            }
        }
    }
    ::execution::EmptyMessage response;
    const auto grpc_status = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncInsertBodies, stub_, request, response, grpc_context_);
    if (!grpc_status.ok()) {
        log::Error() << "RemoteClient::insert_bodies error: " << grpc_status.error_message();
    }
}

}  // namespace silkworm::execution
