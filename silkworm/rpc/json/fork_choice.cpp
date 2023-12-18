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

#include "fork_choice.hpp"

#include <cstring>
#include <utility>

#include <silkworm/core/common/util.hpp>

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
