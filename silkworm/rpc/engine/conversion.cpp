// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "conversion.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/empty_hashes.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::rpc::engine {

using namespace execution::api;

class PayloadValidationError : public std::logic_error {
  public:
    PayloadValidationError() : std::logic_error("payload validation error, unknown reason") {}

    explicit PayloadValidationError(const std::string& reason) : std::logic_error(reason) {}
};

rpc::ForkChoiceUpdatedReply fork_choice_updated_reply_from_result(const ForkChoiceResult& result) {
    rpc::ForkChoiceUpdatedReply reply;
    switch (result.status) {
        case ExecutionStatus::kSuccess:
            reply.payload_status = rpc::PayloadStatus::kAccepted;
            break;
        case ExecutionStatus::kInvalidForkchoice:
            reply.payload_status.status = rpc::PayloadStatus::kInvalidStr;
            break;
        case ExecutionStatus::kBadBlock:
            reply.payload_status.status = rpc::PayloadStatus::kInvalidBlockHashStr;
            break;
        case ExecutionStatus::kBusy:
        case ExecutionStatus::kMissingSegment:
        case ExecutionStatus::kTooFarAway:
            reply.payload_status.status = rpc::PayloadStatus::kSyncingStr;
            break;
    }
    if (!result) {
        reply.payload_status.latest_valid_hash = result.latest_valid_head;
        reply.payload_status.validation_error = result.validation_error;
    }
    return reply;
}

rpc::ExecutionPayloadBodies execution_payloads_from_bodies(const execution::api::BlockBodies& bodies) {
    rpc::ExecutionPayloadBodies payload_bodies;
    payload_bodies.resize(bodies.size());
    for (const auto& block_body : bodies) {
        std::vector<Bytes> rlp_txs;
        rlp_txs.reserve(block_body.transactions.size());
        for (const auto& transaction : block_body.transactions) {
            Bytes tx_rlp;
            rlp::encode(tx_rlp, transaction);
            rlp_txs.emplace_back(tx_rlp.data(), tx_rlp.size());
        }
        rpc::ExecutionPayloadBody payload_body{
            .transactions = std::move(rlp_txs),
            .withdrawals = block_body.withdrawals,
        };
        payload_bodies.push_back(std::move(payload_body));
    }
    return payload_bodies;
}

std::shared_ptr<Block> block_from_execution_payload(const rpc::ExecutionPayload& payload) {
    std::shared_ptr<Block> block = std::make_shared<Block>();
    BlockHeader& header = block->header;

    header.number = payload.block_num;
    header.timestamp = payload.timestamp;
    header.parent_hash = payload.parent_hash;
    header.state_root = payload.state_root;
    header.receipts_root = payload.receipts_root;
    header.logs_bloom = payload.logs_bloom;
    header.gas_used = payload.gas_used;
    header.gas_limit = payload.gas_limit;
    header.timestamp = payload.timestamp;
    header.extra_data = payload.extra_data;
    header.base_fee_per_gas = payload.base_fee;
    header.beneficiary = payload.suggested_fee_recipient;

    for (const auto& rlp_encoded_tx : payload.transactions) {
        ByteView rlp_encoded_tx_view{rlp_encoded_tx};
        Transaction tx;
        auto decoding_result = rlp::decode_transaction(rlp_encoded_tx_view, tx, rlp::Eip2718Wrapping::kBoth);
        if (!decoding_result) {
            std::string reason{magic_enum::enum_name<DecodingError>(decoding_result.error())};
            throw PayloadValidationError("tx rlp decoding error: " + reason);
        }
        block->transactions.push_back(tx);
    }
    header.transactions_root = protocol::compute_transaction_root(*block);

    // as per EIP-4895
    if (payload.withdrawals) {
        block->withdrawals = std::vector<Withdrawal>{};
        block->withdrawals->reserve(payload.withdrawals->size());
        std::copy(payload.withdrawals->begin(), payload.withdrawals->end(), std::back_inserter(*block->withdrawals));
        header.withdrawals_root = protocol::compute_withdrawals_root(*block);
    }

    // as per EIP-3675
    header.ommers_hash = kEmptyListHash;  // = Keccak256(RLP([]))
    header.difficulty = 0;
    header.nonce = {0, 0, 0, 0, 0, 0, 0, 0};
    block->ommers = {};  // RLP([]) = 0xc0

    // as per EIP-4399
    header.prev_randao = payload.prev_randao;

    // as per EIP-4844
    header.blob_gas_used = payload.blob_gas_used;
    header.excess_blob_gas = payload.excess_blob_gas;

    return block;
}

}  // namespace silkworm::rpc::engine
