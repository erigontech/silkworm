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
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/rpc/client/call.hpp>
#include <silkworm/infra/rpc/common/conversion.hpp>
#include <silkworm/infra/rpc/interfaces/types.hpp>
#include <silkworm/interfaces/execution/execution.grpc.pb.h>

namespace silkworm::execution {

using namespace std::chrono;
using namespace boost::asio;

static void serialize_header(const BlockHeader& bh, ::execution::Header* header) {
    header->set_allocated_parent_hash(rpc::H256_from_bytes32(bh.parent_hash).release());
    header->set_allocated_coinbase(rpc::H160_from_address(bh.beneficiary).release());
    header->set_allocated_state_root(rpc::H256_from_bytes32(bh.state_root).release());
    header->set_allocated_receipt_root(rpc::H256_from_bytes32(bh.receipts_root).release());
    header->set_allocated_logs_bloom(rpc::H2048_from_string(to_string(bh.logs_bloom)).release());
    header->set_allocated_mix_digest(rpc::H256_from_bytes32(bh.mix_hash).release());
    header->set_block_number(bh.number);
    header->set_gas_limit(bh.gas_limit);
    header->set_gas_used(bh.gas_used);
    header->set_timestamp(bh.timestamp);
    header->set_nonce(endian::load_big_u64(bh.nonce.data()));
    header->set_extra_data(bh.extra_data.data(), bh.extra_data.size());
    header->set_allocated_difficulty(rpc::H256_from_uint256(bh.difficulty).release());
    header->set_allocated_block_hash(rpc::H256_from_bytes32(bh.hash()).release());
    header->set_allocated_ommer_hash(rpc::H256_from_bytes32(bh.ommers_hash).release());
    header->set_allocated_transaction_hash(rpc::H256_from_bytes32(bh.transactions_root).release());
    if (bh.base_fee_per_gas) {
        header->set_allocated_base_fee_per_gas(rpc::H256_from_uint256(*bh.base_fee_per_gas).release());
    }
    if (bh.withdrawals_root) {
        header->set_allocated_withdrawal_hash(rpc::H256_from_bytes32(*bh.withdrawals_root).release());
    }
    if (bh.excess_data_gas) {
        header->set_allocated_excess_data_gas(rpc::H256_from_uint256(*bh.excess_data_gas).release());
    }
}

static void deserialize_header(const ::execution::Header& received_header, BlockHeader& header) {
    header.parent_hash = rpc::bytes32_from_H256(received_header.parent_hash());
    header.beneficiary = rpc::address_from_H160(received_header.coinbase());
    header.state_root = rpc::bytes32_from_H256(received_header.state_root());
    header.receipts_root = rpc::bytes32_from_H256(received_header.receipt_root());
    const auto& logs_bloom = rpc::string_from_H2048(received_header.logs_bloom());
    std::copy(logs_bloom.cbegin(), logs_bloom.cend(), header.logs_bloom.begin());
    header.mix_hash = rpc::bytes32_from_H256(received_header.mix_digest());
    header.number = received_header.block_number();
    header.gas_limit = received_header.gas_limit();
    header.gas_used = received_header.gas_used();
    header.timestamp = received_header.timestamp();
    endian::store_big_u64(header.nonce.data(), received_header.nonce());
    std::copy(received_header.extra_data().cbegin(), received_header.extra_data().cend(), header.extra_data.begin());
    header.difficulty = rpc::uint256_from_H256(received_header.difficulty());
    header.ommers_hash = rpc::bytes32_from_H256(received_header.ommer_hash());
    header.transactions_root = rpc::bytes32_from_H256(received_header.transaction_hash());
    if (received_header.has_base_fee_per_gas()) {
        header.base_fee_per_gas = rpc::uint256_from_H256(received_header.base_fee_per_gas());
    }
    if (received_header.has_withdrawal_hash()) {
        header.withdrawals_root = rpc::bytes32_from_H256(received_header.withdrawal_hash());
    }
    if (received_header.has_excess_data_gas()) {
        header.excess_data_gas = rpc::uint256_from_H256(received_header.excess_data_gas());
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

RemoteClient::RemoteClient(agrpc::GrpcContext& grpc_context, const std::shared_ptr<grpc::Channel>& channel)
    : grpc_context_(grpc_context), stub_(::execution::Execution::NewStub(channel)) {}

awaitable<void> RemoteClient::start() {
    throw std::runtime_error{"RemoteClient::start not implemented"};
}

awaitable<BlockHeader> RemoteClient::get_header(BlockNum block_number, Hash block_hash) {
    BlockHeader header;
    ::execution::GetSegmentRequest request;
    request.set_block_number(block_number);
    request.set_allocated_block_hash(rpc::H256_from_bytes32(block_hash).release());

    const auto response = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncGetHeader, stub_, request, grpc_context_, "failure getting header");

    const auto& received_header = response.header();
    match_or_throw(block_hash, received_header.block_hash());
    match_or_throw(block_number, received_header.block_number());

    deserialize_header(received_header, header);

    co_return header;
}

awaitable<BlockBody> RemoteClient::get_body(BlockNum block_number, Hash block_hash) {
    BlockBody body;
    ::execution::GetSegmentRequest request;
    request.set_block_number(block_number);
    request.set_allocated_block_hash(rpc::H256_from_bytes32(block_hash).release());

    const auto response = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncGetBody, stub_, request, grpc_context_, "failure getting body");

    const auto& received_body = response.body();
    match_or_throw(block_hash, received_body.block_hash());
    match_or_throw(block_number, received_body.block_number());

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
            .validator_index = execution_withdrawal.validator_index(),
            .address = rpc::address_from_H160(execution_withdrawal.address()),
            .amount = execution_withdrawal.amount(),
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
    co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncInsertHeaders, stub_, request, grpc_context_, "failure inserting headers");
}

awaitable<void> RemoteClient::insert_bodies(const BlockVector& blocks) {
    ::execution::InsertBodiesRequest request;
    for (const auto& b : blocks) {
        ::execution::BlockBody* body = request.add_bodies();
        body->set_allocated_block_hash(rpc::H256_from_bytes32(b.header.hash()).release());
        body->set_block_number(b.header.number);
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
                w->set_validator_index(withdrawal.validator_index);
                w->set_allocated_address(rpc::H160_from_address(withdrawal.address).release());
                w->set_amount(withdrawal.amount);
            }
        }
    }
    co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncInsertBodies, stub_, request, grpc_context_, "failure inserting bodies");
}

awaitable<bool> RemoteClient::is_canonical(Hash block_hash) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(block_hash);
    const auto response = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncIsCanonicalHash, stub_, *request, grpc_context_, "failure checking canonical hash");

    co_return response.canonical();
}

awaitable<BlockNum> RemoteClient::get_block_num(Hash block_hash) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(block_hash);
    const auto response = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncGetHeaderHashNumber, stub_, *request, grpc_context_, "failure getting block number");

    co_return response.block_number();
}

awaitable<ValidationResult> RemoteClient::validate_chain(Hash head_block_hash) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(head_block_hash);
    const auto response = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncValidateChain, stub_, *request, grpc_context_, "failure verifying chain");

    ValidationResult result;
    switch (response.validation_status()) {
        case ::execution::ValidationStatus::Success:
            result = ValidChain{.current_head = hash_from_H256(response.latest_valid_hash())};
            break;
        case ::execution::ValidationStatus::InvalidChain:
            result = InvalidChain{.latest_valid_head = hash_from_H256(response.latest_valid_hash())};
            break;
        case ::execution::ValidationStatus::TooFarAway:
        case ::execution::ValidationStatus::MissingSegment:
            result = ValidationError{.latest_valid_head = hash_from_H256(response.latest_valid_hash()),
                                     .missing_block = hash_from_H256(response.missing_hash())};
            break;
        default:
            throw std::runtime_error("unknown validation status");
    }

    co_return result;
};

awaitable<ForkChoiceApplication> RemoteClient::update_fork_choice(Hash head_block_hash, std::optional<Hash> /*finalized_block_hash*/) {
    std::unique_ptr<types::H256> request = rpc::H256_from_bytes32(head_block_hash);
    const auto response = co_await rpc::unary_rpc(
        &::execution::Execution::Stub::AsyncUpdateForkChoice, stub_, *request, grpc_context_, "failure updating fork choice");

    ForkChoiceApplication result{.success = response.success(), .current_head = hash_from_H256(response.latest_valid_hash())};

    co_return result;
}

}  // namespace silkworm::execution
