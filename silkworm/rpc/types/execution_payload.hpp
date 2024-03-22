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
#include <silkworm/core/types/hash.hpp>
#include <silkworm/core/types/withdrawal.hpp>

namespace silkworm::rpc {

//! Capabilities as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/common.md#engine_exchangecapabilities
using Capabilities = std::vector<std::string>;

//! ExecutionPayload represents either
//! ExecutionPayloadV1 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#executionpayloadv1
//! or
//! ExecutionPayloadV2 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#executionpayloadv2
//! or
//! ExecutionPayloadV3 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#executionpayloadv3
struct ExecutionPayload {
    enum Version : uint8_t {
        V1 = 1,
        V2 = 2,
        V3 = 3
    } version{V1};

    BlockNum number{0};
    uint64_t timestamp{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    evmc::address suggested_fee_recipient;
    evmc::bytes32 state_root;
    evmc::bytes32 receipts_root;
    evmc::bytes32 parent_hash;
    evmc::bytes32 block_hash;
    evmc::bytes32 prev_randao;
    intx::uint256 base_fee;
    Bloom logs_bloom{};
    Bytes extra_data;
    std::vector<Bytes> transactions;
    std::optional<std::vector<Withdrawal>> withdrawals;  // present iff version == V2
    std::optional<uint64_t> blob_gas_used;               // present iff version == V3
    std::optional<uint64_t> excess_blob_gas;             // present iff version == V3
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
//! or
//! PayloadAttributesV3 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#payloadattributesv3
struct PayloadAttributes {
    enum Version : uint8_t {
        V1 = 1,
        V2 = 2,
        V3 = 3
    } version{V1};

    uint64_t timestamp{0};
    evmc::bytes32 prev_randao;
    evmc::address suggested_fee_recipient;
    std::optional<std::vector<Withdrawal>> withdrawals;     // present iff version == V2
    std::optional<evmc::bytes32> parent_beacon_block_root;  // present iff version == V3
};

struct NewPayloadRequest {
    rpc::ExecutionPayload execution_payload;
    std::optional<std::vector<Hash>> expected_blob_versioned_hashes;
    std::optional<evmc::bytes32> parent_beacon_block_root;
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

inline bool operator==(const PayloadStatus& lhs, const PayloadStatus& rhs) {
    return lhs.status == rhs.status;
}

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
    std::optional<std::vector<Bytes>> transactions;      // not present iff requested block is missing
    std::optional<std::vector<Withdrawal>> withdrawals;  // present iff after Shanghai
};
using ExecutionPayloadBodies = std::vector<ExecutionPayloadBody>;

//! BlobsBundleV1 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#blobsbundlev1
struct BlobsBundle {
    using KZGCommitment = std::array<uint8_t, 48>;
    using KZGProof = std::array<uint8_t, 48>;
    using Blob = std::array<uint8_t, 131072>;

    std::vector<KZGCommitment> commitments;
    std::vector<KZGProof> proofs;
    std::vector<Blob> blobs;
};

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
