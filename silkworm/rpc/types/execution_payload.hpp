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

#pragma once

#include <optional>
#include <string>
#include <vector>

#include <evmc/evmc.hpp>
#include <intx/intx.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/types/bloom.hpp>
#include <silkworm/core/types/withdrawal.hpp>

namespace silkworm::rpc {

//! Capabilities as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#engine_exchangecapabilities
using Capabilities = std::vector<std::string>;

//! ExecutionPayload represents either
//! ExecutionPayloadV1 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#executionpayloadv1
//! or
//! ExecutionPayloadV2 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#executionpayloadv2
struct ExecutionPayload {
    enum Version : uint32_t {
        V1 = 1,
        V2 = 2
    } version{V1};

    BlockNum number;
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
    Bloom logs_bloom;
    Bytes extra_data;
    std::vector<Bytes> transactions;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};  // present iff version == V2
};

//! ForkChoiceStateV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#forkchoicestatev1
struct ForkChoiceState {
    evmc::bytes32 head_block_hash;
    evmc::bytes32 safe_block_hash;
    evmc::bytes32 finalized_block_hash;
};

//! PayloadAttributes represents either
//! PayloadAttributesV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#payloadattributesv1
//! or
//! PayloadAttributesV2 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#payloadattributesv2
struct PayloadAttributes {
    enum Version : uint32_t {
        V1 = 1,
        V2 = 2
    } version{V1};

    uint64_t timestamp;
    evmc::bytes32 prev_randao;
    evmc::address suggested_fee_recipient;
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};  // present iff version == V2
};

//! PayloadStatusV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#payloadstatusv1
struct PayloadStatus {
    static inline const char* kValid{"VALID"};
    static inline const char* kInvalid{"INVALID"};
    static inline const char* kSyncing{"SYNCING"};
    static inline const char* kAccepted{"ACCEPTED"};
    static inline const char* kInvalidBlockHash{"INVALID_BLOCK_HASH"};
    static const PayloadStatus Syncing;
    static const PayloadStatus Accepted;
    static const PayloadStatus InvalidBlockHash;

    std::string status;
    std::optional<evmc::bytes32> latest_valid_hash;
    std::optional<std::string> validation_error;
};

inline const PayloadStatus PayloadStatus::Syncing{.status = PayloadStatus::kSyncing};
inline const PayloadStatus PayloadStatus::Accepted{.status = PayloadStatus::kAccepted};
inline const PayloadStatus PayloadStatus::InvalidBlockHash{.status = PayloadStatus::kInvalidBlockHash};

struct ForkChoiceUpdatedRequest {
    ForkChoiceState fork_choice_state;
    std::optional<PayloadAttributes> payload_attributes;
};

struct ForkChoiceUpdatedReply {
    PayloadStatus payload_status;
    std::optional<uint64_t> payload_id;
};

//! TransitionConfigurationV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#transitionconfigurationv1
struct TransitionConfiguration {
    intx::uint256 terminal_total_difficulty;
    evmc::bytes32 terminal_block_hash;
    BlockNum terminal_block_number{0};
};

//! Response for engine_getPayloadV2 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#response-2
struct ExecutionPayloadAndValue {
    ExecutionPayload payload;
    intx::uint256 block_value;  // in wei
};

//! ExecutionPayloadBodyV1 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#executionpayloadbodyv1
struct ExecutionPayloadBody {
    std::optional<std::vector<Bytes>> transactions{std::nullopt};      // not present iff requested block is missing
    std::optional<std::vector<Withdrawal>> withdrawals{std::nullopt};  // present iff after Shanghai
};
using ExecutionPayloadBodies = std::vector<ExecutionPayloadBody>;

std::ostream& operator<<(std::ostream& out, const ExecutionPayload& payload);
std::ostream& operator<<(std::ostream& out, const PayloadStatus& payload_status);
std::ostream& operator<<(std::ostream& out, const ForkChoiceState& fork_choice_state);
std::ostream& operator<<(std::ostream& out, const PayloadAttributes& payload_attributes);
std::ostream& operator<<(std::ostream& out, const ForkChoiceUpdatedRequest& fcu_request);
std::ostream& operator<<(std::ostream& out, const ForkChoiceUpdatedReply& fcu_reply);
std::ostream& operator<<(std::ostream& out, const TransitionConfiguration& transition_configuration);
std::ostream& operator<<(std::ostream& out, const ExecutionPayloadAndValue& pv);
std::ostream& operator<<(std::ostream& out, const ExecutionPayloadBody& body);

}  // namespace silkworm::rpc
