// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        kV1 = 1,
        kV2 = 2,
        kV3 = 3
    } version{kV1};

    BlockNum block_num{0};
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

    std::string to_string() const;
};

//! ForkChoiceStateV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#forkchoicestatev1
struct ForkChoiceState {
    evmc::bytes32 head_block_hash;
    evmc::bytes32 safe_block_hash;
    evmc::bytes32 finalized_block_hash;

    std::string to_string() const;
};

//! PayloadAttributes represents either
//! PayloadAttributesV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#payloadattributesv1
//! or
//! PayloadAttributesV2 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#payloadattributesv2
//! or
//! PayloadAttributesV3 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/cancun.md#payloadattributesv3
struct PayloadAttributes {
    enum Version : uint8_t {
        kV1 = 1,
        kV2 = 2,
        kV3 = 3
    } version{kV1};

    uint64_t timestamp{0};
    evmc::bytes32 prev_randao;
    evmc::address suggested_fee_recipient;
    std::optional<std::vector<Withdrawal>> withdrawals;     // present iff version == V2
    std::optional<evmc::bytes32> parent_beacon_block_root;  // present iff version == V3

    std::string to_string() const;
};

struct NewPayloadRequest {
    rpc::ExecutionPayload execution_payload;
    std::optional<std::vector<Hash>> expected_blob_versioned_hashes;
    std::optional<evmc::bytes32> parent_beacon_block_root;
    std::optional<std::vector<Bytes>> execution_requests;
};

//! PayloadStatusV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#payloadstatusv1
struct PayloadStatus {
    static constexpr const char* kValidStr{"VALID"};
    static constexpr const char* kInvalidStr{"INVALID"};
    static constexpr const char* kSyncingStr{"SYNCING"};
    static constexpr const char* kAcceptedStr{"ACCEPTED"};
    static constexpr const char* kInvalidBlockHashStr{"INVALID_BLOCK_HASH"};

    static const PayloadStatus kSyncing;
    static const PayloadStatus kAccepted;
    static const PayloadStatus kInvalidBlockHash;

    std::string status;
    std::optional<Hash> latest_valid_hash;
    std::optional<std::string> validation_error;

    std::string to_string() const;
};

inline const PayloadStatus PayloadStatus::kSyncing{.status = PayloadStatus::kSyncingStr};
inline const PayloadStatus PayloadStatus::kAccepted{.status = PayloadStatus::kAcceptedStr};
inline const PayloadStatus PayloadStatus::kInvalidBlockHash{.status = PayloadStatus::kInvalidBlockHashStr};

inline bool operator==(const PayloadStatus& lhs, const PayloadStatus& rhs) {
    return lhs.status == rhs.status;
}

struct ForkChoiceUpdatedRequest {
    ForkChoiceState fork_choice_state;
    std::optional<PayloadAttributes> payload_attributes;

    std::string to_string() const;
};

struct ForkChoiceUpdatedReply {
    PayloadStatus payload_status;
    std::optional<uint64_t> payload_id;

    std::string to_string() const;
};

//! TransitionConfigurationV1 as specified by https://github.com/ethereum/execution-apis/blob/main/src/engine/paris.md#transitionconfigurationv1
struct TransitionConfiguration {
    intx::uint256 terminal_total_difficulty;
    evmc::bytes32 terminal_block_hash;
    BlockNum terminal_block_num{0};

    std::string to_string() const;
};

//! Response for engine_getPayloadV2 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#response-2
struct ExecutionPayloadAndValue {
    ExecutionPayload payload;
    intx::uint256 block_value;  // in wei

    std::string to_string() const;
};

//! ExecutionPayloadBodyV1 as specified in https://github.com/ethereum/execution-apis/blob/main/src/engine/shanghai.md#executionpayloadbodyv1
struct ExecutionPayloadBody {
    std::optional<std::vector<Bytes>> transactions;      // not present iff requested block is missing
    std::optional<std::vector<Withdrawal>> withdrawals;  // present iff after Shanghai

    std::string to_string() const;
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
