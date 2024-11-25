/*
   Copyright 2024 The Silkworm Authors

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

#include "direct_service.hpp"

namespace silkworm::execution::api {

DirectService::DirectService(ExecutionEngine& exec_engine)
    : exec_engine_{exec_engine} {}

/** Chain Putters **/

// rpc InsertBlocks(InsertBlocksRequest) returns(InsertionResult);
Task<InsertionResult> DirectService::insert_blocks(const Blocks& blocks) {
    const bool ready_for_insertion{co_await ready()};
    if (!ready_for_insertion) {
        co_return InsertionResult{.status = api::ExecutionStatus::kBusy};
    }
    // TODO(canepat) handle more errors out of insert_blocks (e.g. bad block...)
    exec_engine_.insert_blocks(blocks);
    co_return InsertionResult{.status = api::ExecutionStatus::kSuccess};
}

/** Chain Validation and ForkChoice **/

// rpc ValidateChain(ValidationRequest) returns(ValidationReceipt);
Task<ValidationResult> DirectService::validate_chain(BlockId number_and_hash) {
    const auto verification = co_await exec_engine_.verify_chain(number_and_hash.hash);
    co_return verification;
}

// rpc UpdateForkChoice(ForkChoice) returns(ForkChoiceReceipt);
Task<ForkChoiceResult> DirectService::update_fork_choice(const ForkChoice& fork_choice) {
    const auto& head_block_hash{fork_choice.head_block_hash};
    const auto& finalized_block_hash{fork_choice.finalized_block_hash};
    const auto& safe_block_hash{fork_choice.safe_block_hash};
    const bool updated = exec_engine_.notify_fork_choice_update(head_block_hash,
                                                                finalized_block_hash,
                                                                safe_block_hash);  // BLOCKING, will block the entire io_context thread

    const auto last_fork_choice = exec_engine_.last_fork_choice();
    ForkChoiceResult result{
        .status = updated ? api::ExecutionStatus::kSuccess : api::ExecutionStatus::kInvalidForkchoice,
        .latest_valid_head = last_fork_choice.hash,
        // TODO(canepat) add support for validation error
    };
    co_return result;
}

/** Block Assembly **/

// rpc AssembleBlock(AssembleBlockRequest) returns(AssembleBlockResponse);
Task<AssembleBlockResult> DirectService::assemble_block(const api::BlockUnderConstruction&) {
    // TODO(canepat) not yet supported
    co_return AssembleBlockResult{};
}

// rpc GetAssembledBlock(GetAssembledBlockRequest) returns(GetAssembledBlockResponse);
Task<AssembledBlockResult> DirectService::get_assembled_block(PayloadId) {
    // TODO(canepat) not yet supported
    co_return AssembledBlockResult{};
}

/** Chain Getters **/

// rpc CurrentHeader(google.protobuf.Empty) returns(GetHeaderResponse);
Task<std::optional<BlockHeader>> DirectService::current_header() {
    const auto last_number_and_hash{exec_engine_.last_finalized_block()};
    co_return exec_engine_.get_header(last_number_and_hash.hash);
}

// rpc GetTD(GetSegmentRequest) returns(GetTDResponse);
Task<std::optional<TotalDifficulty>> DirectService::get_td(BlockNumberOrHash number_or_hash) {
    if (std::holds_alternative<Hash>(number_or_hash)) {
        co_return exec_engine_.get_header_td(std::get<Hash>(number_or_hash), std::nullopt);
    } else {
        SILKWORM_ASSERT(std::holds_alternative<BlockNum>(number_or_hash));
        const auto block_num{std::get<BlockNum>(number_or_hash)};
        const auto canonical_hash{exec_engine_.get_canonical_hash(block_num)};
        if (!canonical_hash) {
            co_return std::nullopt;
        }
        co_return exec_engine_.get_header_td(*canonical_hash, block_num);
    }
}

// rpc GetHeader(GetSegmentRequest) returns(GetHeaderResponse);
Task<std::optional<BlockHeader>> DirectService::get_header(BlockNumberOrHash number_or_hash) {
    if (std::holds_alternative<Hash>(number_or_hash)) {
        co_return exec_engine_.get_header(std::get<Hash>(number_or_hash));
    } else {
        SILKWORM_ASSERT(std::holds_alternative<BlockNum>(number_or_hash));
        const auto block_num{std::get<BlockNum>(number_or_hash)};
        co_return exec_engine_.get_canonical_header(block_num);
    }
}

// rpc GetBody(GetSegmentRequest) returns(GetBodyResponse);
Task<std::optional<BlockBody>> DirectService::get_body(BlockNumberOrHash number_or_hash) {
    if (std::holds_alternative<Hash>(number_or_hash)) {
        co_return exec_engine_.get_body(std::get<Hash>(number_or_hash));
    } else {
        SILKWORM_ASSERT(std::holds_alternative<BlockNum>(number_or_hash));
        const auto block_num{std::get<BlockNum>(number_or_hash)};
        co_return exec_engine_.get_canonical_body(block_num);
    }
}

// rpc HasBlock(GetSegmentRequest) returns(HasBlockResponse);
Task<bool> DirectService::has_block(BlockNumberOrHash number_or_hash) {
    if (std::holds_alternative<Hash>(number_or_hash)) {
        co_return exec_engine_.get_header(std::get<Hash>(number_or_hash));
    } else {
        SILKWORM_ASSERT(std::holds_alternative<BlockNum>(number_or_hash));
        const auto block_num{std::get<BlockNum>(number_or_hash)};
        const auto canonical_hash{exec_engine_.get_canonical_hash(block_num)};
        if (!canonical_hash) {
            co_return false;
        }
        co_return exec_engine_.get_header(*canonical_hash);
    }
}

/** Ranges **/

// rpc GetBodiesByRange(GetBodiesByRangeRequest) returns(GetBodiesBatchResponse);
Task<BlockBodies> DirectService::get_bodies_by_range(BlockNumRange number_range) {
    BlockBodies bodies;
    const auto [start_block_num, end_block_num] = number_range;
    if (start_block_num > end_block_num) {
        co_return bodies;
    }
    bodies.reserve(end_block_num - start_block_num + 1);
    for (BlockNum number{start_block_num}; number <= end_block_num; ++number) {
        auto block_body{exec_engine_.get_canonical_body(number)};
        auto block_hash{exec_engine_.get_canonical_hash(number)};
        if (block_body && block_hash) {
            bodies.push_back(Body{std::move(*block_body), *block_hash, number});
        } else {
            // Add an empty body anyway because we must respond w/ one payload for each number
            bodies.emplace_back();
        }
    }
    co_return bodies;
}

// rpc GetBodiesByHashes(GetBodiesByHashesRequest) returns(GetBodiesBatchResponse);
Task<BlockBodies> DirectService::get_bodies_by_hashes(const BlockHashes& hashes) {
    BlockBodies bodies;
    bodies.reserve(hashes.size());
    for (const auto& block_hash : hashes) {
        auto block_body{exec_engine_.get_body(block_hash)};
        auto block_num{exec_engine_.get_block_num(block_hash)};
        if (block_body && block_num) {
            bodies.push_back(Body{std::move(*block_body), block_hash, *block_num});
        } else {
            // Add an empty body anyway because we must respond w/ one payload for each hash
            bodies.emplace_back();
        }
    }
    co_return bodies;
}

/** Chain Checkers **/

// rpc IsCanonicalHash(types.H256) returns(IsCanonicalResponse);
Task<bool> DirectService::is_canonical_hash(Hash block_hash) {
    co_return exec_engine_.is_canonical(block_hash);
}

// rpc GetHeaderHashNumber(types.H256) returns(GetHeaderHashNumberResponse);
Task<std::optional<BlockNum>> DirectService::get_header_hash_number(Hash block_hash) {
    co_return exec_engine_.get_block_num(block_hash);
}

// rpc GetForkChoice(google.protobuf.Empty) returns(ForkChoice);
Task<ForkChoice> DirectService::get_fork_choice() {
    const auto last_fork_choice_number_and_hash{exec_engine_.last_fork_choice()};
    const auto last_finalized_number_and_hash{exec_engine_.last_finalized_block()};
    const auto last_safe_number_and_hash{exec_engine_.last_safe_block()};
    ForkChoice last_fork_choice{
        .head_block_hash = last_fork_choice_number_and_hash.hash,
        .finalized_block_hash = last_finalized_number_and_hash.hash,
        .safe_block_hash = last_safe_number_and_hash.hash,
    };
    co_return last_fork_choice;
}

/** Misc **/

// rpc Ready(google.protobuf.Empty) returns(ReadyResponse);
Task<bool> DirectService::ready() {
    // TODO(canepat) use semaphore to sync access to the database wrt block execution
    co_return true;
}

// rpc FrozenBlocks(google.protobuf.Empty) returns(FrozenBlocksResponse);
Task<uint64_t> DirectService::frozen_blocks() {
    co_return exec_engine_.highest_frozen_block_num();
}

/** Additional non-RPC methods **/

Task<BlockHeaders> DirectService::get_last_headers(uint64_t n) {
    co_return exec_engine_.get_last_headers(n);
}

Task<BlockNum> DirectService::block_progress() {
    co_return exec_engine_.block_progress();
}

}  // namespace silkworm::execution::api
