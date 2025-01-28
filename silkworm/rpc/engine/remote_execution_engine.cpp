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

#include "remote_execution_engine.hpp"

#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/rpc/protocol/errors.hpp>

#include "conversion.hpp"
#include "validation.hpp"

namespace silkworm::rpc::engine {

using namespace concurrency::awaitable_wait_for_one;
using namespace execution::api;

Task<PayloadStatus> RemoteExecutionEngine::new_payload(const NewPayloadRequest& request, Msec timeout) {
    const auto& payload{request.execution_payload};

    // Make the execution full block from the block payload
    auto block = block_from_execution_payload(payload);

    if (request.parent_beacon_block_root) {
        block->header.parent_beacon_block_root = request.parent_beacon_block_root;
    }

    // Validations
    if (const auto result = validate_blob_hashes(*block, request.expected_blob_versioned_hashes); !result) {
        co_return PayloadStatus{rpc::PayloadStatus::kInvalidStr, {}, result.error()};
    }

    const Hash block_hash = block->header.hash();
    if (payload.block_hash != block_hash) {
        co_return PayloadStatus::kInvalidBlockHash;
    }

    // Insert the new block
    std::vector<std::shared_ptr<Block>> blocks{std::move(block)};
    const auto insert_result = co_await execution_service_->insert_blocks(blocks);
    if (!insert_result) {
        co_return PayloadStatus::kSyncing;
    }

    // Retrieve back the block number
    const auto block_num = co_await execution_service_->get_header_hash_number(block_hash);
    if (!block_num) {
        co_return PayloadStatus::kAccepted;
    }

    const auto verification = co_await (execution_service_->validate_chain({*block_num, block_hash}) || concurrency::timeout(timeout));

    if (std::holds_alternative<ValidChain>(verification)) {  // VALID
        co_return PayloadStatus{.status = PayloadStatus::kValidStr, .latest_valid_hash = block_hash};
    } else if (std::holds_alternative<InvalidChain>(verification)) {  // INVALID
        const auto invalid_chain = std::get<InvalidChain>(verification);
        co_return PayloadStatus{.status = PayloadStatus::kInvalidStr, .latest_valid_hash = invalid_chain.unwind_point.hash};
    } else {  // ERROR
        const auto validation_error = std::get<ValidationError>(verification);
        co_return PayloadStatus{PayloadStatus::kInvalidStr, {}, validation_error.error};
    }
}

Task<ForkChoiceUpdatedReply> RemoteExecutionEngine::fork_choice_updated(const ForkChoiceUpdatedRequest& request, Msec timeout) {
    const ForkChoice fork_choice{
        request.fork_choice_state.head_block_hash,
        static_cast<uint64_t>(timeout.count()),
        request.fork_choice_state.finalized_block_hash,
        request.fork_choice_state.safe_block_hash,
    };
    const auto fork_choice_result = co_await execution_service_->update_fork_choice(fork_choice);
    co_return fork_choice_updated_reply_from_result(fork_choice_result);
}

Task<ExecutionPayloadAndValue> RemoteExecutionEngine::get_payload(uint64_t /*payload_id*/, Msec /*timeout*/) {
    // We do not support the payload building process yet, so any payload ID is unknown
    throw boost::system::system_error{to_system_code(ErrorCode::kUnknownPayload)};
}

Task<ExecutionPayloadBodies> RemoteExecutionEngine::get_payload_bodies_by_hash(const std::vector<Hash>& block_hashes, Msec timeout) {
    const auto result = co_await (execution_service_->get_bodies_by_hashes(block_hashes) || concurrency::timeout(timeout));
    ensure(std::holds_alternative<BlockBodies>(result), "get_payload_bodies_by_hash: unexpected awaitable operators outcome");
    const auto block_bodies = std::get<BlockBodies>(result);
    ensure(block_bodies.size() == block_hashes.size(), "get_payload_bodies_by_hash: number of hashes and bodies do not match");
    co_return execution_payloads_from_bodies(block_bodies);
}

Task<ExecutionPayloadBodies> RemoteExecutionEngine::get_payload_bodies_by_range(BlockNum start, uint64_t count, Msec timeout) {
    ensure(count >= 1, "get_payload_bodies_by_range: invalid count zero");
    const BlockNumRange block_num_range{start, start + count - 1};
    const auto result = co_await (execution_service_->get_bodies_by_range(block_num_range) || concurrency::timeout(timeout));
    ensure(std::holds_alternative<BlockBodies>(result), "get_payload_bodies_by_hash: unexpected awaitable operators outcome");
    const auto block_bodies = std::get<BlockBodies>(result);
    ensure(block_bodies.size() == count, "get_payload_bodies_by_range: number of bodies and count do not match");
    co_return execution_payloads_from_bodies(block_bodies);
}

}  // namespace silkworm::rpc::engine
