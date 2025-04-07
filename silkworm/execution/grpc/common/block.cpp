// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "block.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>

namespace silkworm::execution::grpc {

namespace proto = ::execution;

void deserialize_hex_as_bytes(std::string_view hex, std::vector<Bytes>& sequence) {
    auto blob_bytes{from_hex(hex)};
    if (blob_bytes) {
        sequence.push_back(std::move(*blob_bytes));
    }
}

void header_from_proto(const ::execution::Header& proto_header, BlockHeader& header) {
    header.parent_hash = rpc::bytes32_from_h256(proto_header.parent_hash());
    header.ommers_hash = rpc::bytes32_from_h256(proto_header.ommer_hash());
    header.beneficiary = rpc::address_from_h160(proto_header.coinbase());
    header.state_root = rpc::bytes32_from_h256(proto_header.state_root());
    header.transactions_root = rpc::bytes32_from_h256(proto_header.transaction_hash());
    header.receipts_root = rpc::bytes32_from_h256(proto_header.receipt_root());
    header.difficulty = rpc::uint256_from_h256(proto_header.difficulty());
    header.number = proto_header.block_number();
    header.gas_limit = proto_header.gas_limit();
    header.gas_used = proto_header.gas_used();
    header.timestamp = proto_header.timestamp();
    header.prev_randao = rpc::bytes32_from_h256(proto_header.prev_randao());
    rpc::span_from_h2048(proto_header.logs_bloom(), header.logs_bloom);
    endian::store_big_u64(header.nonce.data(), proto_header.nonce());
    header.extra_data = string_view_to_byte_view(proto_header.extra_data());
    if (proto_header.has_base_fee_per_gas()) {
        header.base_fee_per_gas = rpc::uint256_from_h256(proto_header.base_fee_per_gas());
    }
    if (proto_header.has_withdrawal_hash()) {
        header.withdrawals_root = rpc::bytes32_from_h256(proto_header.withdrawal_hash());
    }
    if (proto_header.has_blob_gas_used()) {
        header.blob_gas_used = proto_header.blob_gas_used();
    }
    if (proto_header.has_excess_blob_gas()) {
        header.excess_blob_gas = proto_header.excess_blob_gas();
    }
    if (proto_header.has_requests_hash()) {
        header.requests_hash = rpc::bytes32_from_h256(proto_header.requests_hash());
    }
}

BlockHeader header_from_proto(const proto::Header& proto_header) {
    BlockHeader header;
    header_from_proto(proto_header, header);
    return header;
}

void body_from_proto(const ::execution::BlockBody& proto_body, BlockBody& body, Hash& block_hash, BlockNum& block_num) {
    block_hash = rpc::bytes32_from_h256(proto_body.block_hash());
    block_num = proto_body.block_number();
    body.transactions.reserve(static_cast<size_t>(proto_body.transactions_size()));
    for (const auto& received_tx : proto_body.transactions()) {
        ByteView raw_tx_rlp{string_view_to_byte_view(received_tx)};
        Transaction tx;
        rlp::decode(raw_tx_rlp, tx);
        body.transactions.push_back(std::move(tx));
    }
    body.ommers.reserve(static_cast<size_t>(proto_body.uncles_size()));
    for (const auto& received_ommer : proto_body.uncles()) {
        body.ommers.emplace_back(header_from_proto(received_ommer));
    }
    if (proto_body.withdrawals_size() > 0) {
        std::vector<Withdrawal> withdrawals;
        withdrawals.reserve(static_cast<size_t>(proto_body.withdrawals_size()));
        body.withdrawals = std::move(withdrawals);
    }
    for (const auto& received_withdrawal : proto_body.withdrawals()) {
        body.withdrawals->emplace_back(withdrawal_from_proto_type(received_withdrawal));
    }
}

api::Body body_from_proto(const proto::BlockBody& proto_body) {
    api::Body body;
    body_from_proto(proto_body, body, body.block_hash, body.block_num);
    return body;
}

void proto_from_header(const BlockHeader& bh, proto::Header* header) {
    header->set_allocated_parent_hash(rpc::h256_from_bytes32(bh.parent_hash).release());
    header->set_allocated_coinbase(rpc::h160_from_address(bh.beneficiary).release());
    header->set_allocated_state_root(rpc::h256_from_bytes32(bh.state_root).release());
    header->set_allocated_receipt_root(rpc::h256_from_bytes32(bh.receipts_root).release());
    header->set_allocated_logs_bloom(rpc::h2048_from_string(to_string(bh.logs_bloom)).release());
    header->set_allocated_prev_randao(rpc::h256_from_bytes32(bh.prev_randao).release());
    header->set_block_number(bh.number);
    header->set_gas_limit(bh.gas_limit);
    header->set_gas_used(bh.gas_used);
    header->set_timestamp(bh.timestamp);
    header->set_nonce(endian::load_big_u64(bh.nonce.data()));
    header->set_allocated_extra_data(new std::string{byte_ptr_cast(bh.extra_data.data()), bh.extra_data.size()});
    header->set_allocated_difficulty(rpc::h256_from_uint256(bh.difficulty).release());
    header->set_allocated_block_hash(rpc::h256_from_bytes32(bh.hash()).release());
    header->set_allocated_ommer_hash(rpc::h256_from_bytes32(bh.ommers_hash).release());
    header->set_allocated_transaction_hash(rpc::h256_from_bytes32(bh.transactions_root).release());
    if (bh.base_fee_per_gas) {
        header->set_allocated_base_fee_per_gas(rpc::h256_from_uint256(*bh.base_fee_per_gas).release());
    }
    if (bh.withdrawals_root) {
        header->set_allocated_withdrawal_hash(rpc::h256_from_bytes32(*bh.withdrawals_root).release());
    }
    if (bh.blob_gas_used) {
        header->set_blob_gas_used(*bh.blob_gas_used);
    }
    if (bh.excess_blob_gas) {
        header->set_excess_blob_gas(*bh.excess_blob_gas);
    }
    if (bh.requests_hash) {
        header->set_allocated_requests_hash(rpc::h256_from_bytes32(*bh.requests_hash).release());
    }
}

void proto_from_body(const BlockBody& body, const Hash& h, BlockNum n, proto::BlockBody* proto_body) {
    proto_body->set_allocated_block_hash(rpc::h256_from_bytes32(h).release());
    proto_body->set_block_number(n);
    for (const auto& transaction : body.transactions) {
        Bytes tx_rlp;
        rlp::encode(tx_rlp, transaction);
        proto_body->add_transactions(tx_rlp.data(), tx_rlp.size());
    }
    for (const auto& ommer : body.ommers) {
        proto::Header* uncle = proto_body->add_uncles();
        proto_from_header(ommer, uncle);
    }
    if (body.withdrawals) {
        for (const auto& withdrawal : *body.withdrawals) {
            ::types::Withdrawal* w = proto_body->add_withdrawals();
            serialize_withdrawal(withdrawal, w);
        }
    }
}

void proto_from_body(const api::Body& body, proto::BlockBody* proto_body) {
    proto_from_body(body, body.block_hash, body.block_num, proto_body);
}

void proto_from_body(const Block& block, ::execution::BlockBody* proto_body) {
    proto_from_body(block, block.header.hash(), block.header.number, proto_body);
}

void serialize_withdrawal(const Withdrawal& withdrawal, ::types::Withdrawal* w) {
    w->set_index(withdrawal.index);
    w->set_validator_index(withdrawal.validator_index);
    w->set_allocated_address(rpc::h160_from_address(withdrawal.address).release());
    w->set_amount(withdrawal.amount);
}

Withdrawal withdrawal_from_proto_type(const ::types::Withdrawal& w) {
    return {
        .index = w.index(),
        .validator_index = w.validator_index(),
        .address = rpc::address_from_h160(w.address()),
        .amount = w.amount(),
    };
}

}  // namespace silkworm::execution::grpc
