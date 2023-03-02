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

#include "sync_engine_pos.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/consensus/base/engine.hpp>
#include <silkworm/node/common/measure.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

namespace silkworm::chainsync::pos {

static void ensure_invariant(bool condition, std::string message) {
    if (!condition)
        throw std::logic_error("Consensus invariant violation: " + message);
}

class PayloadValidationError : public std::logic_error {
  public:
    PayloadValidationError() : std::logic_error("payload validation error, unknown reason") {}

    explicit PayloadValidationError(const std::string& reason) : std::logic_error(reason) {}
};

PoSSync::PoSSync(BlockExchange& be, stagedsync::ExecutionEngine& ee)
    : block_exchange_{be},
      exec_engine_{ee},
      chain_fork_view_{ee.get_canonical_head(), ee} {
    // BlockExchange need a starting point to start downloading from
    block_exchange_.initial_state(exec_engine_.get_last_headers(65536));
}

// Wait for blocks arrival from BlockExchange and insert them into ExecutionEngine
void PoSSync::execution_loop() {
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

// Convert an ExecutionPayload to a Block as per "Engine API - Paris" specs
Block PoSSync::make_execution_block(const ExecutionPayload& payload) {
    Block block;
    BlockHeader& header = block.header;

    header.number = payload.number;
    header.timestamp = payload.timestamp;
    header.parent_hash = payload.parent_hash;
    header.state_root = payload.state_root;
    header.receipts_root = payload.receipts_root;
    header.logs_bloom = payload.logs_bloom;
    header.gas_used = payload.gas_used;
    header.gas_limit = payload.gas_limit;
    header.timestamp = payload.timestamp;
    header.extra_data = payload.extra_data;
    header.base_fee_per_gas = payload.base_fee;
    header.beneficiary = payload.suggested_fee_recipient;

    for (const auto& rlp_encoded_tx : payload.transactions) {
        ByteView rlp_encoded_tx_view{rlp_encoded_tx};
        Transaction tx;
        auto decoding_result = rlp::decode_transaction(rlp_encoded_tx_view, tx, rlp::Eip2718Wrapping::kBoth);
        if (!decoding_result) {
            std::string reason{magic_enum::enum_name<DecodingError>(decoding_result.error())};
            throw PayloadValidationError("tx rlp decoding error: " + reason);
        }
        block.transactions.push_back(tx);
    }
    header.transactions_root = consensus::EngineBase::compute_transaction_root(block);

    // as per EIP-3675
    header.ommers_hash = kEmptyListHash;  // = Keccak256(RLP([]))
    header.difficulty = 0;
    header.mix_hash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    header.nonce = {0, 0, 0, 0, 0, 0, 0, 0};
    block.ommers = {};  // RLP([]) = 0xc0

    // as per EIP-4399
    if (payload.number >= TRANSITION_BLOCK) {
        header.mix_hash = payload.prev_randao;
    }

    return block;
}

void PoSSync::validate_execution_block(evmc::bytes32 /*blockHash*/, const Block&) {
    // use consensus VerifyHeader?
}

bool PoSSync::extends_canonical(const Block& block, Hash block_hash) {
    // specs are not clear on the meaning of extends_canonical, we implement this as follows
    return exec_engine_.extends_last_fork_choice(block.header.number, block_hash);  // todo: use chain_fork_view_ cache?
}

PayloadStatus PoSSync::new_payload(const ExecutionPayload& payload, seconds_t /*timeout*/) {
    using ValidChain = stagedsync::ExecutionEngine::ValidChain;
    using InvalidChain = stagedsync::ExecutionEngine::InvalidChain;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;

    try {
        Block block = make_execution_block(payload);  // as per the EngineAPI spec

        Hash block_hash = block.header.hash();
        if (payload.block_hash != block_hash) return {.status = PayloadStatus::kInvalidBlockHash};

        validate_execution_block(payload.block_hash, block);

        auto parent = exec_engine_.get_header(block.header.parent_hash);  // todo: use chain_fork_view_ cache?
        if (!parent) {
            // send payload to the block exchange to extend the chain up to it
            block_exchange_.new_target_block(block);
            return {.status = PayloadStatus::kSyncing};  // .latestValidHash = nullopt
        }

        if (!extends_canonical(block, block_hash)) {
            return {PayloadStatus::kAccepted};  // .latestValidHash = nullopt
        }

        exec_engine_.insert_block(block);
        auto verification = exec_engine_.verify_chain(block_hash);

        if (std::holds_alternative<ValidChain>(verification)) {
            // VALID
            return {.status = PayloadStatus::kValid, .latest_valid_hash = block_hash};
        } else if (std::holds_alternative<InvalidChain>(verification)) {
            // INVALID
            auto invalid_chain = std::get<InvalidChain>(verification);
            Hash latest_valid_hash = invalid_chain.unwind_point < TRANSITION_BLOCK
                                         ? kZeroHash
                                         : invalid_chain.unwind_head;  // todo: check!
            return {.status = PayloadStatus::kInvalid, .latest_valid_hash = latest_valid_hash};
        } else {
            // ERROR
            return {PayloadStatus::kInvalid, std::nullopt, "unknown execution error"};
        }

    } catch (const PayloadValidationError& e) {
        log::Error("Sync") << "Error processing payload: " << e.what();
        return {PayloadStatus::kInvalid, std::nullopt, e.what()};
    } catch (const std::exception& e) {
        log::Error("Sync") << "Error processing payload: " << e.what();
        return {PayloadStatus::kInvalid, std::nullopt, e.what()};
    }
}

PayloadStatus PoSSync::fork_choice_update(const ForkChoiceState& /*state*/,
                                          const std::optional<PayloadAttributes>& /*attributes*/, seconds_t /*timeout*/) {
    // Implementation of engine_forkchoiceUpdatedV1 method
    ensure_invariant(false, "fork_choice_update not implemented");
    return {.status = PayloadStatus::kInvalid};
}

ExecutionPayload PoSSync::get_payload(std::string /*payloadId*/, seconds_t /*timeout*/) {
    // Implementation of engine_getPayloadV1 method
    ensure_invariant(false, "get_payload not implemented");
    return {};
}

TransitionConfiguration PoSSync::exchange_transition_config(const TransitionConfiguration& /*config*/, seconds_t /*timeout*/) {
    // Implementation of engine_exchangeTransitionConfigurationV1 method
    ensure_invariant(false, "exchange_transition_config not implemented");
    return {};
}

}  // namespace silkworm::chainsync::pos