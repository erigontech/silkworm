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

#include "active_direct_service.hpp"

#include <silkworm/infra/concurrency/co_spawn_sw.hpp>

namespace silkworm::execution::api {

ActiveDirectService::ActiveDirectService(stagedsync::ExecutionEngine& exec_engine, boost::asio::io_context& context)
    : DirectService{exec_engine}, context_{context}, executor_{context_.get_executor()} {}

void ActiveDirectService::execution_loop() {
    exec_engine_.open();

    boost::asio::executor_work_guard<decltype(executor_)> work{executor_};
    context_.run();

    exec_engine_.close();
}

bool ActiveDirectService::stop() {
    context_.stop();
    return ActiveComponent::stop();
}

/** Chain Putters **/

// rpc InsertBlocks(InsertBlocksRequest) returns(InsertionResult);
Task<InsertionResult> ActiveDirectService::insert_blocks(const Blocks& blocks) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, const auto& bb) {
        return self->DirectService::insert_blocks(bb);
    }(this, blocks));
}

/** Chain Validation and ForkChoice **/

// rpc ValidateChain(ValidationRequest) returns(ValidationReceipt);
Task<ValidationResult> ActiveDirectService::validate_chain(BlockNumAndHash number_and_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto num_and_hash) {
        return self->DirectService::validate_chain(num_and_hash);
    }(this, number_and_hash));
}

// rpc UpdateForkChoice(ForkChoice) returns(ForkChoiceReceipt);
Task<ForkChoiceResult> ActiveDirectService::update_fork_choice(const ForkChoice& fork_choice) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, const auto& choice) {
        return self->DirectService::update_fork_choice(choice);
    }(this, fork_choice));
}

/** Block Assembly **/

// rpc AssembleBlock(AssembleBlockRequest) returns(AssembleBlockResponse);
Task<AssembleBlockResult> ActiveDirectService::assemble_block(const api::BlockUnderConstruction& block) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, const auto& b) {
        return self->DirectService::assemble_block(b);
    }(this, block));
}

// rpc GetAssembledBlock(GetAssembledBlockRequest) returns(GetAssembledBlockResponse);
Task<AssembledBlockResult> ActiveDirectService::get_assembled_block(PayloadId payload_id) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto id) {
        return self->DirectService::get_assembled_block(id);
    }(this, payload_id));
}

/** Chain Getters **/

// rpc CurrentHeader(google.protobuf.Empty) returns(GetHeaderResponse);
Task<std::optional<BlockHeader>> ActiveDirectService::current_header() {
    return concurrency::co_spawn_and_await(executor_, [](auto* self) {
        return self->DirectService::current_header();
    }(this));
}

// rpc GetTD(GetSegmentRequest) returns(GetTDResponse);
Task<std::optional<TotalDifficulty>> ActiveDirectService::get_td(BlockNumberOrHash number_or_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto num_or_hash) {
        return self->DirectService::get_td(num_or_hash);
    }(this, number_or_hash));
}

// rpc GetHeader(GetSegmentRequest) returns(GetHeaderResponse);
Task<std::optional<BlockHeader>> ActiveDirectService::get_header(BlockNumberOrHash number_or_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto num_or_hash) {
        return self->DirectService::get_header(num_or_hash);
    }(this, number_or_hash));
}

// rpc GetBody(GetSegmentRequest) returns(GetBodyResponse);
Task<std::optional<BlockBody>> ActiveDirectService::get_body(BlockNumberOrHash number_or_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto num_or_hash) {
        return self->DirectService::get_body(num_or_hash);
    }(this, number_or_hash));
}

// rpc HasBlock(GetSegmentRequest) returns(HasBlockResponse);
Task<bool> ActiveDirectService::has_block(BlockNumberOrHash number_or_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto num_or_hash) {
        return self->DirectService::has_block(num_or_hash);
    }(this, number_or_hash));
}

/** Ranges **/

// rpc GetBodiesByRange(GetBodiesByRangeRequest) returns(GetBodiesBatchResponse);
Task<BlockBodies> ActiveDirectService::get_bodies_by_range(BlockNumRange number_range) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto num_range) {
        return self->DirectService::get_bodies_by_range(num_range);
    }(this, number_range));
}

// rpc GetBodiesByHashes(GetBodiesByHashesRequest) returns(GetBodiesBatchResponse);
Task<BlockBodies> ActiveDirectService::get_bodies_by_hashes(const BlockHashes& hashes) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, const auto& hh) {
        return self->DirectService::get_bodies_by_hashes(hh);
    }(this, hashes));
}

/** Chain Checkers **/

// rpc IsCanonicalHash(types.H256) returns(IsCanonicalResponse);
Task<bool> ActiveDirectService::is_canonical_hash(Hash block_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto h) {
        return self->DirectService::is_canonical_hash(h);
    }(this, block_hash));
}

// rpc GetHeaderHashNumber(types.H256) returns(GetHeaderHashNumberResponse);
Task<std::optional<BlockNum>> ActiveDirectService::get_header_hash_number(Hash block_hash) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto h) {
        return self->DirectService::get_header_hash_number(h);
    }(this, block_hash));
}

// rpc GetForkChoice(google.protobuf.Empty) returns(ForkChoice);
Task<ForkChoice> ActiveDirectService::get_fork_choice() {
    return concurrency::co_spawn_and_await(executor_, [](auto* self) {
        return self->DirectService::get_fork_choice();
    }(this));
}

/** Misc **/

// rpc Ready(google.protobuf.Empty) returns(ReadyResponse);
Task<bool> ActiveDirectService::ready() {
    return concurrency::co_spawn_and_await(executor_, [](auto* self) {
        return self->DirectService::ready();
    }(this));
}

// rpc FrozenBlocks(google.protobuf.Empty) returns(FrozenBlocksResponse);
Task<uint64_t> ActiveDirectService::frozen_blocks() {
    return concurrency::co_spawn_and_await(executor_, [](auto* self) {
        return self->DirectService::frozen_blocks();
    }(this));
}

/** Additional non-RPC methods **/

Task<BlockHeaders> ActiveDirectService::get_last_headers(uint64_t n) {
    return concurrency::co_spawn_and_await(executor_, [](auto* self, auto how_many) {
        return self->DirectService::get_last_headers(how_many);
    }(this, n));
}

Task<BlockNum> ActiveDirectService::block_progress() {
    return concurrency::co_spawn_and_await(executor_, [](auto* self) {
        return self->DirectService::block_progress();
    }(this));
}

}  // namespace silkworm::execution::api
