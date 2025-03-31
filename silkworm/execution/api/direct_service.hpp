// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "execution_engine.hpp"
#include "service.hpp"

namespace silkworm::execution::api {

//! Straightforward asynchronous implementation of Execution API service relying on \code ExecutionEngine.
//! This is used both client-side by 'direct' (i.e. no-gRPC) implementation and server-side by gRPC server.
class DirectService : public Service {
  public:
    explicit DirectService(ExecutionEngine& exec_engine);
    ~DirectService() override = default;

    DirectService(const DirectService&) = delete;
    DirectService& operator=(const DirectService&) = delete;

    DirectService(DirectService&&) = delete;
    DirectService& operator=(DirectService&&) = delete;

    /** Chain Putters **/

    // rpc InsertBlocks(InsertBlocksRequest) returns(InsertionResult);
    Task<InsertionResult> insert_blocks(const Blocks& blocks) override;

    /** Chain Validation and ForkChoice **/

    // rpc ValidateChain(ValidationRequest) returns(ValidationReceipt);
    Task<ValidationResult> validate_chain(BlockId block_id) override;

    // rpc UpdateForkChoice(ForkChoice) returns(ForkChoiceReceipt);
    Task<ForkChoiceResult> update_fork_choice(const ForkChoice& fork_choice) override;

    /** Block Assembly **/

    // rpc AssembleBlock(AssembleBlockRequest) returns(AssembleBlockResponse);
    Task<AssembleBlockResult> assemble_block(const BlockUnderConstruction&) override;

    // rpc GetAssembledBlock(GetAssembledBlockRequest) returns(GetAssembledBlockResponse);
    Task<AssembledBlockResult> get_assembled_block(PayloadId id) override;

    /** Chain Getters **/

    // rpc CurrentHeader(google.protobuf.Empty) returns(GetHeaderResponse);
    Task<std::optional<BlockHeader>> current_header() override;

    // rpc GetTD(GetSegmentRequest) returns(GetTDResponse);
    Task<std::optional<TotalDifficulty>> get_td(BlockNumOrHash block_num_or_hash) override;

    // rpc GetHeader(GetSegmentRequest) returns(GetHeaderResponse);
    Task<std::optional<BlockHeader>> get_header(BlockNumOrHash block_num_or_hash) override;

    // rpc GetBody(GetSegmentRequest) returns(GetBodyResponse);
    Task<std::optional<BlockBody>> get_body(BlockNumOrHash block_num_or_hash) override;

    // rpc HasBlock(GetSegmentRequest) returns(HasBlockResponse);
    Task<bool> has_block(BlockNumOrHash block_num_or_hash) override;

    /** Ranges **/

    // rpc GetBodiesByRange(GetBodiesByRangeRequest) returns(GetBodiesBatchResponse);
    Task<BlockBodies> get_bodies_by_range(BlockNumRange range) override;

    // rpc GetBodiesByHashes(GetBodiesByHashesRequest) returns(GetBodiesBatchResponse);
    Task<BlockBodies> get_bodies_by_hashes(const BlockHashes& hashes) override;

    /** Chain Checkers **/

    // rpc IsCanonicalHash(types.H256) returns(IsCanonicalResponse);
    Task<bool> is_canonical_hash(Hash block_hash) override;

    // rpc GetHeaderHashNumber(types.H256) returns(GetHeaderHashNumberResponse);
    Task<std::optional<BlockNum>> get_header_hash_number(Hash block_hash) override;

    // rpc GetForkChoice(google.protobuf.Empty) returns(ForkChoice);
    Task<ForkChoice> get_fork_choice() override;

    /** Misc **/

    // rpc Ready(google.protobuf.Empty) returns(ReadyResponse);
    Task<bool> ready() override;

    // rpc FrozenBlocks(google.protobuf.Empty) returns(FrozenBlocksResponse);
    Task<uint64_t> frozen_blocks() override;

    /** Additional non-RPC methods **/

    Task<BlockHeaders> get_last_headers(uint64_t n) override;

    Task<BlockNum> block_progress() override;

  protected:
    ExecutionEngine& exec_engine_;
};

}  // namespace silkworm::execution::api
