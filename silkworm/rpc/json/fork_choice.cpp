// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "fork_choice.hpp"

#include "types.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const ForkChoiceState& forkchoice_state) {
    json["headBlockHash"] = forkchoice_state.head_block_hash;
    json["safeBlockHash"] = forkchoice_state.safe_block_hash;
    json["finalizedBlockHash"] = forkchoice_state.finalized_block_hash;
}

void from_json(const nlohmann::json& json, ForkChoiceState& forkchoice_state) {
    forkchoice_state = ForkChoiceState{
        .head_block_hash = json.at("headBlockHash").get<evmc::bytes32>(),
        .safe_block_hash = json.at("safeBlockHash").get<evmc::bytes32>(),
        .finalized_block_hash = json.at("finalizedBlockHash").get<evmc::bytes32>()};
}

void to_json(nlohmann::json& json, const ForkChoiceUpdatedReply& forkchoice_updated_reply) {
    nlohmann::json json_payload_status = forkchoice_updated_reply.payload_status;
    json["payloadStatus"] = json_payload_status;
    if (forkchoice_updated_reply.payload_id) {
        json["payloadId"] = to_hex(forkchoice_updated_reply.payload_id.value());
    }
}

}  // namespace silkworm::rpc
