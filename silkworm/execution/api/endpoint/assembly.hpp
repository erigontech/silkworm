// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <vector>

#include <evmc/evmc.hpp>

#include <silkworm/core/types/block.hpp>

namespace silkworm::execution::api {

using PayloadId = uint64_t;

struct BlockUnderConstruction {
    Hash parent_hash;
    uint64_t timestamp{0};
    evmc::bytes32 prev_randao;
    evmc::address suggested_fee_recipient;
    std::optional<std::vector<Withdrawal>> withdrawals;
    std::optional<Hash> parent_beacon_block_root;
};

struct AssembleBlockResult {
    bool success{false};
    PayloadId payload_id{0};
};

using ListOfBytes = std::vector<Bytes>;

struct ExecutionPayload {
    uint32_t version{0};
    Hash parent_hash;
    evmc::address suggested_fee_recipient;
    Hash state_root;
    Hash receipts_root;
    Bloom logs_bloom{};
    evmc::bytes32 prev_randao;
    BlockNum block_num{0};
    uint64_t gas_limit{0};
    uint64_t gas_used{0};
    uint64_t timestamp{0};
    Bytes extra_data;
    intx::uint256 base_fee_per_gas;
    Hash block_hash;
    std::vector<Bytes> transactions;
    std::optional<std::vector<Withdrawal>> withdrawals;
    std::optional<uint64_t> blob_gas_used;
    std::optional<uint64_t> excess_blob_gas;
};

struct BlobsBundleV1 {
    ListOfBytes commitments;
    ListOfBytes blobs;
    ListOfBytes proofs;
};

struct AssembledBlock {
    ExecutionPayload execution_payload;
    Hash block_hash;
    BlobsBundleV1 blobs_bundle;
};

struct AssembledBlockResult {
    bool success{false};
    std::optional<AssembledBlock> data;
};

}  // namespace silkworm::execution::api
