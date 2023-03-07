/*
   Copyright 2020 The Silkrpc Authors

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

#pragma once

#include <vector>
#include <optional>
#include <string>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/types/bloom.hpp>

namespace silkrpc {

//! ExecutionPayload as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md
struct ExecutionPayload {
    uint64_t number;
    uint64_t timestamp;
    uint64_t gas_limit;
    uint64_t gas_used;
    evmc::address suggested_fee_recipient;
    evmc::bytes32 state_root;
    evmc::bytes32 receipts_root;
    evmc::bytes32 parent_hash;
    evmc::bytes32 block_hash;
    evmc::bytes32 prev_randao;
    intx::uint256 base_fee;
    silkworm::Bloom logs_bloom;
    silkworm::Bytes extra_data;
    std::vector<silkworm::Bytes> transactions;
};

//! ForkChoiceState as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#ForkchoiceStateV1
struct ForkChoiceState {
    evmc::bytes32 head_block_hash;
    evmc::bytes32 safe_block_hash;
    evmc::bytes32 finalized_block_hash;
};

//! PayloadAttributes as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md#payloadattributesv1
struct PayloadAttributes {
    uint64_t timestamp;
    evmc::bytes32 prev_randao;
    evmc::address suggested_fee_recipient;
};

//! PayloadStatus as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md
struct PayloadStatus {
    std::string status;
    std::optional<evmc::bytes32> latest_valid_hash;
    std::optional<std::string> validation_error;
};

struct ForkChoiceUpdatedRequest {
    ForkChoiceState fork_choice_state;
    std::optional<PayloadAttributes> payload_attributes;
};

struct ForkChoiceUpdatedReply {
    PayloadStatus payload_status;
    std::optional<uint64_t> payload_id;
};

//! TransitionConfiguration as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/specification.md
struct TransitionConfiguration {
    intx::uint256 terminal_total_difficulty;
    evmc::bytes32 terminal_block_hash;
    uint64_t terminal_block_number{0};
};

std::ostream& operator<<(std::ostream& out, const ExecutionPayload& payload);
std::ostream& operator<<(std::ostream& out, const PayloadStatus& payload_status);
std::ostream& operator<<(std::ostream& out, const ForkChoiceState& fork_choice_state);
std::ostream& operator<<(std::ostream& out, const PayloadAttributes& payload_attributes);
std::ostream& operator<<(std::ostream& out, const ForkChoiceUpdatedReply& fork_choice_updated_reply);
std::ostream& operator<<(std::ostream& out, const TransitionConfiguration& transition_configuration);

} // namespace silkrpc

