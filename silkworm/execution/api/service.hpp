// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <functional>
#include <memory>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/types/hash.hpp>

#include "endpoint/assembly.hpp"
#include "endpoint/checkers.hpp"
#include "endpoint/getters.hpp"
#include "endpoint/insertion.hpp"
#include "endpoint/range.hpp"
#include "endpoint/validation.hpp"

namespace silkworm::execution::api {

//! Common Execution API definition for both in-process and out-of-process client/server
struct Service {
    virtual ~Service() = default;

    /** Chain Putters **/

    // rpc InsertBlocks(InsertBlocksRequest) returns(InsertionResult);
    virtual Task<InsertionResult> insert_blocks(const Blocks&) = 0;

    /** Chain Validation and ForkChoice **/

    // rpc ValidateChain(ValidationRequest) returns(ValidationReceipt);
    virtual Task<ValidationResult> validate_chain(BlockId) = 0;

    // rpc UpdateForkChoice(ForkChoice) returns(ForkChoiceReceipt);
    virtual Task<ForkChoiceResult> update_fork_choice(const ForkChoice&) = 0;

    /** Block Assembly **/

    // rpc AssembleBlock(AssembleBlockRequest) returns(AssembleBlockResponse);
    virtual Task<AssembleBlockResult> assemble_block(const api::BlockUnderConstruction&) = 0;

    // rpc GetAssembledBlock(GetAssembledBlockRequest) returns(GetAssembledBlockResponse);
    virtual Task<AssembledBlockResult> get_assembled_block(PayloadId) = 0;

    /** Chain Getters **/

    // rpc CurrentHeader(google.protobuf.Empty) returns(GetHeaderResponse);
    virtual Task<std::optional<BlockHeader>> current_header() = 0;

    // rpc GetTD(GetSegmentRequest) returns(GetTDResponse);
    virtual Task<std::optional<TotalDifficulty>> get_td(BlockNumOrHash) = 0;

    // rpc GetHeader(GetSegmentRequest) returns(GetHeaderResponse);
    virtual Task<std::optional<BlockHeader>> get_header(BlockNumOrHash) = 0;

    // rpc GetBody(GetSegmentRequest) returns(GetBodyResponse);
    virtual Task<std::optional<BlockBody>> get_body(BlockNumOrHash) = 0;

    // rpc HasBlock(GetSegmentRequest) returns(HasBlockResponse);
    virtual Task<bool> has_block(BlockNumOrHash) = 0;

    /** Ranges **/

    // rpc GetBodiesByRange(GetBodiesByRangeRequest) returns(GetBodiesBatchResponse);
    virtual Task<BlockBodies> get_bodies_by_range(BlockNumRange) = 0;

    // rpc GetBodiesByHashes(GetBodiesByHashesRequest) returns(GetBodiesBatchResponse);
    virtual Task<BlockBodies> get_bodies_by_hashes(const BlockHashes&) = 0;

    /** Chain Checkers **/

    // rpc IsCanonicalHash(types.H256) returns(IsCanonicalResponse);
    virtual Task<bool> is_canonical_hash(Hash block_hash) = 0;

    // rpc GetHeaderHashNumber(types.H256) returns(GetHeaderHashNumberResponse);
    virtual Task<std::optional<BlockNum>> get_header_hash_number(Hash block_hash) = 0;

    // rpc GetForkChoice(google.protobuf.Empty) returns(ForkChoice);
    virtual Task<ForkChoice> get_fork_choice() = 0;

    /** Misc **/

    // rpc Ready(google.protobuf.Empty) returns(ReadyResponse);
    virtual Task<bool> ready() = 0;

    // rpc FrozenBlocks(google.protobuf.Empty) returns(FrozenBlocksResponse);
    virtual Task<uint64_t> frozen_blocks() = 0;

    /** Additional non-RPC methods **/

    virtual Task<BlockHeaders> get_last_headers(uint64_t n) = 0;

    virtual Task<BlockNum> block_progress() = 0;
};

}  // namespace silkworm::execution::api
