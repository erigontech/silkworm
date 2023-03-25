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
#include <silkworm/node/rpc/interfaces/types.hpp>

namespace silkworm::execution {

using namespace std::chrono;
using namespace boost::asio;

static void serialize_header(const BlockHeader& bh, ::execution::Header* header) {
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

static void deserialize_header(const ::execution::Header& received_header, BlockHeader& header) {
    header.parent_hash = rpc::bytes32_from_H256(received_header.parenthash());
    header.beneficiary = rpc::address_from_H160(received_header.coinbase());
    header.state_root = rpc::bytes32_from_H256(received_header.stateroot());
    header.receipts_root = rpc::bytes32_from_H256(received_header.receiptroot());
    const auto& logs_bloom = rpc::string_from_H2048(received_header.logsbloom());
    std::copy(logs_bloom.cbegin(), logs_bloom.cend(), header.logs_bloom.begin());
    header.mix_hash = rpc::bytes32_from_H256(received_header.mixdigest());
    header.number = received_header.blocknumber();
    header.gas_limit = received_header.gaslimit();
    header.gas_used = received_header.gasused();
    header.timestamp = received_header.timestamp();
    endian::store_big_u64(header.nonce.data(), received_header.nonce());
    std::copy(received_header.extradata().cbegin(), received_header.extradata().cend(), header.extra_data.begin());
    header.difficulty = rpc::uint256_from_H256(received_header.difficulty());
    header.ommers_hash = rpc::bytes32_from_H256(received_header.ommerhash());
    header.transactions_root = rpc::bytes32_from_H256(received_header.transactionhash());
    if (received_header.has_basefeepergas()) {
        header.base_fee_per_gas = rpc::uint256_from_H256(received_header.basefeepergas());
    }
    if (received_header.has_withdrawalhash()) {
        header.withdrawals_root = rpc::bytes32_from_H256(received_header.withdrawalhash());
    }
}

static void match_or_throw(const Hash& block_hash, const types::H256& received_hash) {
    const auto& received_block_hash = rpc::bytes32_from_H256(received_hash);
    if (received_block_hash != block_hash) {
        const auto msg =
            "Hash mismatch in received header:"
            " got=" +
            to_hex(received_block_hash) + " expected=" + to_hex(block_hash);
        log::Error() << msg;
        throw std::logic_error{msg};
    }
}

static void match_or_throw(BlockNum block_number, uint64_t received_number) {
    if (block_number != received_number) {
        const auto msg =
            "Number mismatch in received header:"
            " got=" +
            std::to_string(received_number) + " expected=" + std::to_string(block_number);
        log::Error() << msg;
        throw std::logic_error{msg};
    }
}

void stop_if_error(const grpc::Status& status, std::string error_message) {
    if (status.ok()) return;
    throw std::runtime_error{"RemoteClient, " + error_message + ", cause: " + status.error_message()};
}

RemoteClient::RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel)
    : grpc_context_(grpc_context), stub_(::execution::Execution::NewStub(channel)) {}

awaitable<void> RemoteClient::start() {
    throw std::runtime_error{"RemoteClient::start not implemented"};
}

awaitable<BlockHeader> RemoteClient::get_header(BlockNum block_number, Hash block_hash) {
    BlockHeader header;
    ::execution::GetSegmentRequest request;
    request.set_blocknumber(block_number);
    request.set_allocated_blockhash(rpc::H256_from_bytes32(block_hash).release());
    ::execution::GetHeaderResponse response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncGetHeader,
                                                     stub_, request, response, grpc_context_);
    stop_if_error(grpc_status, "failed getting header");

    const auto& received_header = response.header();
    match_or_throw(block_hash, received_header.blockhash());
    match_or_throw(block_number, received_header.blocknumber());

    deserialize_header(received_header, header);

    co_return header;
}

awaitable<BlockBody> RemoteClient::get_body(BlockNum block_number, Hash block_hash) {
    BlockBody body;
    ::execution::GetSegmentRequest request;
    request.set_blocknumber(block_number);
    request.set_allocated_blockhash(rpc::H256_from_bytes32(block_hash).release());
    ::execution::GetBodyResponse response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncGetBody,
                                                     stub_, request, response, grpc_context_);
    stop_if_error(grpc_status, "failed getting body");

    const auto& received_body = response.body();
    match_or_throw(block_hash, received_body.blockhash());
    match_or_throw(block_number, received_body.blocknumber());

    body.transactions.reserve(static_cast<std::size_t>(received_body.transactions_size()));
    for (const auto& execution_tx : received_body.transactions()) {
        ByteView raw_tx_rlp{reinterpret_cast<const uint8_t*>(execution_tx.data()), execution_tx.size()};
        Transaction tx;
        rlp::decode(raw_tx_rlp, tx);
        body.transactions.push_back(std::move(tx));
    }
    body.ommers.reserve(static_cast<std::size_t>(received_body.uncles_size()));
    for (const auto& execution_ommer : received_body.uncles()) {
        BlockHeader ommer;
        deserialize_header(execution_ommer, ommer);
        body.ommers.push_back(std::move(ommer));
    }
    if (received_body.withdrawals_size() > 0) {
        std::vector<Withdrawal> withdrawals;
        withdrawals.reserve(static_cast<std::size_t>(received_body.withdrawals_size()));
        body.withdrawals = std::move(withdrawals);
    }
    for (const auto& execution_withdrawal : received_body.withdrawals()) {
        body.withdrawals->emplace_back(Withdrawal{
            .index = execution_withdrawal.index(),
            .validator_index = execution_withdrawal.validatorindex(),
            .address = rpc::address_from_H160(execution_withdrawal.address()),
            .amount = uint64_t(rpc::uint256_from_H256(execution_withdrawal.amount())),
        });
    }
    co_return body;
}

awaitable<void> RemoteClient::insert_headers(const BlockVector& blocks) {
    ::execution::InsertHeadersRequest request;
    for (const auto& b : blocks) {
        ::execution::Header* header = request.add_headers();
        serialize_header(b.header, header);
    }
    ::execution::EmptyMessage response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncInsertHeaders,
                                                     stub_, request, response, grpc_context_);
    stop_if_error(grpc_status, "failed inserting headers");
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
            serialize_header(ommer, uncle);
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
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncInsertBodies,
                                                     stub_, request, response, grpc_context_);
    stop_if_error(grpc_status, "failed inserting bodies");
}

awaitable<bool> RemoteClient::is_canonical(Hash block_hash) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(block_hash);
    ::execution::IsCanonicalResponse response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncIsCanonicalHash,
                                                     stub_, *request, response, grpc_context_);
    stop_if_error(grpc_status, "failed checking canonical hash");
    co_return response.canonical();
}

awaitable<BlockNum> RemoteClient::get_block_num(Hash block_hash) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(block_hash);
    ::execution::GetHeaderHashNumberResponse response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncGetHeaderHashNumber,
                                                     stub_, *request, response, grpc_context_);
    stop_if_error(grpc_status, "failed getting block number");
    co_return response.blocknumber();
}

awaitable<ValidationResult> RemoteClient::validate_chain(Hash head_block_hash) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(head_block_hash);
    ::execution::ValidationReceipt response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncValidateChain,
                                                     stub_, *request, response, grpc_context_);
    stop_if_error(grpc_status, "failed verifying chain");

    ValidationResult result;
    switch (response.validationstatus()) {
        case ::execution::ValidationStatus::Success:
            result = ValidChain{.current_head = hash_from_H256(response.latestvalidhash())};
        case ::execution::ValidationStatus::InvalidChain:
            result = InvalidChain{.latest_valid_head = hash_from_H256(response.latestvalidhash())};
        case ::execution::ValidationStatus::TooFarAway:
        case ::execution::ValidationStatus::MissingSegment:
            result = ValidationError{.latest_valid_head = hash_from_H256(response.latestvalidhash()),
                                     .missing_block = hash_from_H256(response.missinghash())};
        default:
            throw std::runtime_error("unknown validation status");
    }

    co_return result;
};

awaitable<ForkChoiceApplication> RemoteClient::update_fork_choice(Hash head_block_hash, std::optional<Hash> /*finalized_block_hash*/) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(head_block_hash);
    ::execution::ForkChoiceReceipt response;
    const auto grpc_status = co_await rpc::unary_rpc(&::execution::Execution::Stub::AsyncUpdateForkChoice,
                                                     stub_, *request, response, grpc_context_);
    stop_if_error(grpc_status, "failed updating fork choice");

    ForkChoiceApplication result{.success = response.success(), .current_head = hash_from_H256(response.latestvalidhash())};

    co_return result;
}

}  // namespace silkworm::execution
