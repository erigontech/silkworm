// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "execution_payload.hpp"

#include <silkworm/core/types/address.hpp>
#include <silkworm/core/types/evmc_bytes32.hpp>
#include <silkworm/rpc/common/util.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const ExecutionPayload& payload) {
    auto bloom_bytes{silkworm::ByteView(&payload.logs_bloom[0], 256)};
    out << "version: " << payload.version
        << " block_num: " << payload.block_num
        << " block_hash: " << to_hex(payload.block_hash)
        << " parent_hash: " << to_hex(payload.parent_hash)
        << " timestamp: " << payload.timestamp
        << " gas_limit: " << payload.gas_limit
        << " gas_used: " << payload.gas_used
        << " suggested_fee_recipient: " << payload.suggested_fee_recipient
        << " state_root: " << to_hex(payload.state_root)
        << " receipts_root: " << to_hex(payload.receipts_root)
        << " prev_randao: " << to_hex(payload.prev_randao)
        << " logs_bloom: " << silkworm::to_hex(bloom_bytes)
        << " extra_data: " << silkworm::to_hex(payload.extra_data)
        << " #transactions: " << payload.transactions.size();
    if (payload.withdrawals) {
        out << " #withdrawals: " << payload.withdrawals->size();
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const PayloadStatus& payload_status) {
    out << "status: " << payload_status.status;
    if (payload_status.latest_valid_hash) {
        out << " latest_valid_hash: " << to_hex(*payload_status.latest_valid_hash);
    }
    if (payload_status.validation_error) {
        out << " validation_error: " << *payload_status.validation_error;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ForkChoiceState& fork_choice_state) {
    out << "head_block_hash: " << to_hex(fork_choice_state.head_block_hash)
        << " safe_block_hash: " << to_hex(fork_choice_state.safe_block_hash)
        << " finalized_block_hash: " << to_hex(fork_choice_state.finalized_block_hash);
    return out;
}

std::ostream& operator<<(std::ostream& out, const PayloadAttributes& attributes) {
    out << "version: " << attributes.version
        << " timestamp: " << attributes.timestamp
        << " prev_randao: " << to_hex(attributes.prev_randao)
        << " suggested_fee_recipient: " << attributes.suggested_fee_recipient;
    if (attributes.withdrawals) {
        out << " #withdrawals: " << attributes.withdrawals->size();
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ForkChoiceUpdatedRequest& fcu_request) {
    out << fcu_request.fork_choice_state;
    if (fcu_request.payload_attributes) {
        out << " " << *fcu_request.payload_attributes;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const ForkChoiceUpdatedReply& fcu_reply) {
    out << fcu_reply.payload_status;
    if (fcu_reply.payload_id) {
        out << " payload_id: " << *fcu_reply.payload_id;
    }
    return out;
}

std::ostream& operator<<(std::ostream& out, const TransitionConfiguration& transition_configuration) {
    out << "terminal_total_difficulty: " << transition_configuration.terminal_total_difficulty
        << " terminal_block_hash: " << to_hex(transition_configuration.terminal_block_hash)
        << " terminal_block_num: " << transition_configuration.terminal_block_num;
    return out;
}

std::ostream& operator<<(std::ostream& out, const ExecutionPayloadAndValue& pv) {
    out << "payload: " << pv.payload << " block_value: " << pv.block_value;
    return out;
}

std::ostream& operator<<(std::ostream& out, const ExecutionPayloadBody& body) {
    if (body.transactions) {
        out << "#transactions: " << body.transactions->size();
        if (body.withdrawals) {
            out << " #withdrawals: " << body.withdrawals->size();
        }
    } else {
        out << "null";
    }
    return out;
}

}  // namespace silkworm::rpc
