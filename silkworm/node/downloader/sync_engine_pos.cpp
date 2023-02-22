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

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/node/common/measure.hpp>

#include "sync_engine_pos.hpp"

namespace silkworm::chainsync::pos {

static void ensure_invariant(bool condition, std::string message) {
    if (!condition)
        throw std::logic_error("Consensus invariant violation: " + message);
}

PoSSync::PoSSync(BlockExchange& be, stagedsync::ExecutionEngine& ee)
    : block_exchange_{be},
      exec_engine_{ee},
      chain_fork_view_{ee.get_canonical_head(), ee} {
    // BlockExchange need a starting point to start downloading from
    block_exchange_.initial_state(exec_engine_.get_last_headers(65536));
}

// Wait for blocks arrival from BlockExchange and insert them into ExecutionEngine
void PoSSync::execution_loop() {
    using namespace stagedsync;
    using ValidChain = ExecutionEngine::ValidChain;
    using ValidationError = ExecutionEngine::ValidationError;
    using InvalidChain = ExecutionEngine::InvalidChain;
    using ResultQueue = BlockExchange::ResultQueue;

    ResultQueue& downloading_queue = block_exchange_.result_queue();

    auto initial_block_progress = exec_engine_.get_block_progress();
    auto block_progress = initial_block_progress;

    block_exchange_.download_blocks(block_progress, BlockExchange::Target_Tracking::kByNewPayloads);

    StopWatch timing(StopWatch::kStart);
    RepeatedMeasure<BlockNum> downloaded_headers(initial_block_progress);
    log::Info("Sync") << "Waiting for blocks... from=" << initial_block_progress;

    while (!is_stopping()) {
        Blocks blocks;

        // wait for a batch of blocks
        bool present = downloading_queue.timed_wait_and_pop(blocks, 100ms);
        if (!present) continue;

        // compute head of chain applying fork choice rule
        as_range::for_each(blocks, [&, this](const auto& block) {
            block->td = chain_fork_view_.add(block->header);
            block_progress = std::max(block_progress, block->header.number);
        });

        // insert blocks into database
        exec_engine_.insert_blocks(blocks);

        downloaded_headers.set(block_progress);
        log::Info("Sync") << "Downloading progress: +" << downloaded_headers.delta() << " blocks downloaded, "
                          << downloaded_headers.high_res_throughput<seconds_t>() << " headers/secs"
                          << ", last=" << downloaded_headers.get()
                          << ", head=" << chain_fork_view_.head_height()
                          << ", lap.duration=" << StopWatch::format(timing.since_start());
    };

    block_exchange_.stop_downloading();

    log::Warning("Sync") << "PoS sync loop exited";
}

// a function that convert an ExecutionPayload to a BlockHeader
/*
Block convert(const ExecutionPayload& payload) {

        BlockHeader header;
        header.number = payload.number;

        header.parent_hash = payload.parent_hash;
        header.state_root = payload.state_root;
        header.receipts_root = payload.receipts_root;
        header.logs_bloom = payload.logs_bloom;
        header.gas_used = payload.gas_used;
        header.gas_limit = payload.gas_limit;
        header.timestamp = payload.timestamp;
        header.extra_data = payload.extra_data;
        header.base_fee_per_gas = payload.base_fee;

        header.hash = payload.block_hash;
        header.ommers_hash = payload.ommers_hash;
        header.beneficiary = payload.beneficiary;
        header.transactions_root = payload.transactions_root;
        header.difficulty = payload.difficulty;

        header.mix_hash = payload.mix_hash;
        header.nonce = payload.nonce;

        BlockBody body;
        body.ommers = payload.ommers;
        body.transactions = payload.transactions;

        return {header,body};
}
*/
PayloadStatus PoSSync::new_payload(const ExecutionPayload& payload, seconds_t timeout) {
    /*
    // Implementation of engine_newPayloadV1 method

    auto block = make_ExecutionBlock_from(payload);  // as per the EngineAPI spec

    // send payload to the execution engine, it it respond ok exit
    if (has_parent(block)) {
        exec_engine_.insert_block(block);
        auto verification = exec_engine_.verify_chain(block.hash());
        // todo: handle results
        return PayloadStatus::kValid or not;
    }
    else {
        // send payload to the block exchange to extend the chain up to it
        block_exchange_.new_target_block(block);
    }
    */
}

PayloadStatus PoSSync::fork_choice_update(const ForkChoiceState& state,
                                             const std::optional<PayloadAttributes>& attributes, seconds_t timeout) {
    // Implementation of engine_forkchoiceUpdatedV1 method
}

ExecutionPayload PoSSync::get_payload(std::string payloadId, seconds_t timeout) {
    // Implementation of engine_getPayloadV1 method
}

TransitionConfiguration PoSSync::exchange_transition_config(const TransitionConfiguration& config, seconds_t timeout) {
    // Implementation of engine_exchangeTransitionConfigurationV1 method
}

}  // namespace silkworm::chainsync::pos