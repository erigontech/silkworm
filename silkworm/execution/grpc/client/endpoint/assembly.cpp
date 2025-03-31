// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "assembly.hpp"

#include <silkworm/core/common/bytes_to_string.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>

#include "../../common/block.hpp"

namespace silkworm::execution::grpc::client {

namespace proto = ::execution;

api::ExecutionPayload execution_payload_from_proto(const ::types::ExecutionPayload& payload) {
    api::ExecutionPayload execution_payload;
    execution_payload.version = payload.version();
    execution_payload.parent_hash = rpc::bytes32_from_h256(payload.parent_hash());
    execution_payload.suggested_fee_recipient = rpc::address_from_h160(payload.coinbase());
    execution_payload.state_root = rpc::bytes32_from_h256(payload.state_root());
    execution_payload.receipts_root = rpc::bytes32_from_h256(payload.receipt_root());
    rpc::span_from_h2048(payload.logs_bloom(), execution_payload.logs_bloom);
    execution_payload.prev_randao = rpc::bytes32_from_h256(payload.prev_randao());
    execution_payload.block_num = payload.block_number();
    execution_payload.gas_limit = payload.gas_limit();
    execution_payload.gas_used = payload.gas_used();
    execution_payload.timestamp = payload.timestamp();
    std::copy(payload.extra_data().cbegin(), payload.extra_data().cend(), execution_payload.extra_data.begin());
    execution_payload.base_fee_per_gas = rpc::uint256_from_h256(payload.base_fee_per_gas());
    execution_payload.block_hash = rpc::bytes32_from_h256(payload.block_hash());
    execution_payload.transactions.reserve(static_cast<size_t>(payload.transactions_size()));
    for (const auto& proto_transaction : payload.transactions()) {
        execution_payload.transactions.emplace_back(string_view_to_byte_view(proto_transaction));
    }
    if (payload.withdrawals_size() > 0) {
        std::vector<Withdrawal> withdrawals;
        withdrawals.reserve(static_cast<size_t>(payload.withdrawals_size()));
        execution_payload.withdrawals = std::move(withdrawals);
    }
    for (const auto& proto_withdrawal : payload.withdrawals()) {
        execution_payload.withdrawals->emplace_back(withdrawal_from_proto_type(proto_withdrawal));
    }
    if (payload.has_blob_gas_used()) {
        execution_payload.blob_gas_used = payload.blob_gas_used();
    }
    if (payload.has_excess_blob_gas()) {
        execution_payload.excess_blob_gas = payload.excess_blob_gas();
    }
    return execution_payload;
}

api::BlobsBundleV1 blobs_bundle_from_proto(const ::types::BlobsBundleV1& bundle) {
    api::BlobsBundleV1 blobs_bundle;
    for (int i{0}; i < bundle.commitments_size(); ++i) {
        deserialize_hex_as_bytes(bundle.commitments(i), blobs_bundle.commitments);
    }
    for (int i{0}; i < bundle.blobs_size(); ++i) {
        deserialize_hex_as_bytes(bundle.blobs(i), blobs_bundle.blobs);
    }
    for (int i{0}; i < bundle.proofs_size(); ++i) {
        deserialize_hex_as_bytes(bundle.proofs(i), blobs_bundle.proofs);
    }
    return blobs_bundle;
}

api::AssembledBlock assembled_from_data(const ::execution::AssembledBlockData& data) {
    api::ExecutionPayload payload{execution_payload_from_proto(data.execution_payload())};
    Hash block_hash{rpc::bytes32_from_h256(data.block_value())};
    api::BlobsBundleV1 blobs_bundle{blobs_bundle_from_proto(data.blobs_bundle())};
    return {std::move(payload), block_hash, std::move(blobs_bundle)};
}

proto::AssembleBlockRequest assemble_request_from_block(const api::BlockUnderConstruction& block) {
    proto::AssembleBlockRequest request;
    request.set_timestamp(block.timestamp);
    request.set_allocated_parent_hash(rpc::h256_from_bytes32(block.parent_hash).release());
    request.set_allocated_prev_randao(rpc::h256_from_bytes32(block.prev_randao).release());
    if (block.parent_beacon_block_root) {
        request.set_allocated_parent_beacon_block_root(
            rpc::h256_from_bytes32(*block.parent_beacon_block_root).release());
    }
    request.set_allocated_suggested_fee_recipient(rpc::h160_from_address(block.suggested_fee_recipient).release());
    if (block.withdrawals) {
        for (const auto& withdrawal : *block.withdrawals) {
            ::types::Withdrawal* w{request.add_withdrawals()};
            serialize_withdrawal(withdrawal, w);
        }
    }
    return request;
}

api::AssembleBlockResult assemble_result_from_response(const proto::AssembleBlockResponse& response) {
    api::AssembleBlockResult result{
        .success = !response.busy(),
        .payload_id = response.id(),
    };
    return result;
}

proto::GetAssembledBlockRequest get_assembled_request_from_payload_id(api::PayloadId payload_id) {
    proto::GetAssembledBlockRequest request;
    request.set_id(payload_id);
    return request;
}

api::AssembledBlockResult get_assembled_result_from_response(const proto::GetAssembledBlockResponse& response) {
    api::AssembledBlockResult result{
        .success = !response.busy(),
    };
    if (response.has_data()) {
        result.data = assembled_from_data(response.data());
    }
    return result;
}

}  // namespace silkworm::execution::grpc::client
