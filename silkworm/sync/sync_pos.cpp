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

#include "sync_pos.hpp"

#include <magic_enum.hpp>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/core/protocol/validation.hpp>
#include <silkworm/infra/common/measure.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>

namespace silkworm::chainsync {

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
      chain_fork_view_{ee.get_canonical_head()} {
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
        exec_engine_.insert_blocks(to_plain_blocks(blocks));

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
std::shared_ptr<Block> PoSSync::make_execution_block(const ExecutionPayload& payload) {
    std::shared_ptr<Block> block = std::make_shared<Block>();
    BlockHeader& header = block->header;

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
        block->transactions.push_back(tx);
    }
    header.transactions_root = protocol::compute_transaction_root(block);

    // as per EIP-3675
    header.ommers_hash = kEmptyListHash;  // = Keccak256(RLP([]))
    header.difficulty = 0;
    header.mix_hash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    header.nonce = {0, 0, 0, 0, 0, 0, 0, 0};
    block->ommers = {};  // RLP([]) = 0xc0

    // as per EIP-4399
    header.mix_hash = payload.prev_randao;

    return block;
}

void PoSSync::do_sanity_checks(const BlockHeader& pos_header, const BlockHeader& parent, TotalDifficulty parent_td) {
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;

    if (parent_td < terminal_total_difficulty) throw PayloadValidationError("ignoring pre-merge payload");

    // here Geth checks parent.Difficulty().BitLen() > 0 && gptd != nil && gptd.Cmp(ttd) >= 0 todo: understand
    // auto grand_parent_td = exec_engine_.get_header_td(parent.number - 1, parent.parent_hash);
    // if (parent.difficulty != 0 && grand_parent_td && grand_parent_td >= terminal_total_difficulty)
    //    throw PayloadValidationError("ignoring pre-merge parent block");

    if (pos_header.timestamp <= parent.timestamp) throw PayloadValidationError("invalid timestamp");
    // here Geth return last_valid = fcu head
}

bool PoSSync::extends_canonical(const Block& block, Hash block_hash) {
    // the current canonical is defined by the last FCU, it is from FCU head hash back to the genesis
    return exec_engine_.extends_last_fork_choice(block.header.number, block_hash);
}

auto PoSSync::has_bad_ancestor(const Hash&) -> std::tuple<bool, Hash> {
    return {false, Hash()};  // todo: implement, return if it is valid or the first valid ancestor
}

PayloadStatus PoSSync::new_payload(const ExecutionPayload& payload, seconds_t timeout) {
    // Implementation of engine_new_payloadV1 method
    using namespace stagedsync;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;
    auto no_latest_valid_hash = std::nullopt;

    try {
        auto block = make_execution_block(payload);  // as per the EngineAPI spec

        Hash block_hash = block->header.hash();
        if (payload.block_hash != block_hash) return {.status = PayloadStatus::kInvalidBlockHash};

        auto [valid, last_valid] = has_bad_ancestor(block_hash);
        if (!valid) return {PayloadStatus::kInvalid, last_valid, "bad ancestor"};

        auto parent = exec_engine_.get_header(block->header.parent_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!parent) {
            // send payload to the block exchange to extend the chain up to it
            block_exchange_.new_target_block(*block);
            return {.status = PayloadStatus::kSyncing};
        }
        auto parent_td = exec_engine_.get_header_td(block->header.number - 1, block->header.parent_hash);
        if (!parent_td) {
            return {.status = PayloadStatus::kSyncing};
        }

        do_sanity_checks(block->header, *parent, *parent_td);

        exec_engine_.insert_block(block);

        if (!extends_canonical(*block, block_hash)) {
            return {PayloadStatus::kAccepted};
        }

        // WARNING: from here the method execution can be cancelled
        auto verification = exec_engine_.verify_chain(block_hash).get(timeout);

        if (std::holds_alternative<ValidChain>(verification)) {
            // VALID
            return {.status = PayloadStatus::kValid, .latest_valid_hash = block_hash};
        } else if (std::holds_alternative<InvalidChain>(verification)) {
            // INVALID
            auto invalid_chain = std::get<InvalidChain>(verification);
            auto unwind_point_td = exec_engine_.get_header_td(invalid_chain.unwind_point, invalid_chain.unwind_head);
            Hash latest_valid_hash = unwind_point_td < terminal_total_difficulty
                                         ? kZeroHash
                                         : invalid_chain.unwind_head;
            return {.status = PayloadStatus::kInvalid, .latest_valid_hash = latest_valid_hash};
        } else {
            // ERROR
            return {PayloadStatus::kInvalid, no_latest_valid_hash, "unknown execution error"};
        }

    } catch (const PayloadValidationError& e) {
        log::Error("Sync") << "Error processing payload: " << e.what();
        return {PayloadStatus::kInvalid, no_latest_valid_hash, e.what()};
    } catch (const std::exception& e) {
        log::Error("Sync") << "Error processing payload: " << e.what();
        return {PayloadStatus::kInvalid, no_latest_valid_hash, e.what()};
    }
}

ForkChoiceUpdateReply PoSSync::fork_choice_update(const ForkChoiceState& state,
                                                  const std::optional<PayloadAttributes>& attributes, seconds_t timeout) {
    // Implementation of engine_forkchoiceUpdatedV1 method
    using namespace stagedsync;
    constexpr evmc::bytes32 kZeroHash = 0x0000000000000000000000000000000000000000000000000000000000000000_bytes32;
    auto terminal_total_difficulty = block_exchange_.chain_config().terminal_total_difficulty;
    auto no_latest_valid_hash = std::nullopt;
    auto no_payload_id = std::nullopt;
    try {
        if (!state.head_block_hash) {
            return {{PayloadStatus::kInvalid, no_latest_valid_hash, "invalid head block hash"}, no_payload_id};
        }

        Hash head_header_hash = state.head_block_hash;
        auto head_header = exec_engine_.get_header(head_header_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!head_header) {
            auto [valid, last_valid] = has_bad_ancestor(head_header_hash);
            if (!valid) return {{PayloadStatus::kInvalid, last_valid, "bad ancestor"}, no_payload_id};

            // send payload to the block exchange to extend the chain up to it
            // block_exchange_.new_target_block(head_header_hash);  // todo: implement #############
            return {{.status = PayloadStatus::kSyncing}, no_payload_id};
        }

        BlockId head{head_header->number, head_header_hash};

        auto parent = exec_engine_.get_header(head_header->parent_hash);  // todo: decide whether to use chain_fork_view_ cache instead
        if (!parent) {
            return {{.status = PayloadStatus::kSyncing}, no_payload_id};
        }
        auto parent_td = exec_engine_.get_header_td(head_header->number - 1, head_header->parent_hash);
        if (!parent_td) {
            return {{.status = PayloadStatus::kSyncing}, no_payload_id};
        }

        do_sanity_checks(*head_header, *parent, *parent_td);

        auto last_fcu = exec_engine_.last_fork_choice();
        if (exec_engine_.is_ancestor(head, *last_fcu)) {
            return {{PayloadStatus::kValid, state.head_block_hash}, no_payload_id};
        }

        // WARNING: from here the method execution can be cancelled
        auto verification = exec_engine_.verify_chain(head_header_hash).get(timeout);

        if (std::holds_alternative<InvalidChain>(verification)) {
            // INVALID
            auto invalid_chain = std::get<InvalidChain>(verification);
            auto unwind_point_td = exec_engine_.get_header_td(invalid_chain.unwind_point, invalid_chain.unwind_head);
            Hash latest_valid_hash = unwind_point_td < terminal_total_difficulty
                                         ? kZeroHash
                                         : invalid_chain.unwind_head;
            return {{PayloadStatus::kInvalid, latest_valid_hash}, no_payload_id};
        } else if (!std::holds_alternative<ValidChain>(verification)) {
            // ERROR
            return {{PayloadStatus::kInvalid, no_latest_valid_hash, "unknown execution error"}, no_payload_id};
        }

        // VALID
        // auto valid_chain = std::get<ValidChain>(verification);

        bool valid = exec_engine_.notify_fork_choice_update(state.head_block_hash, state.finalized_block_hash);
        if (!valid) {
            return {{PayloadStatus::kInvalid, no_latest_valid_hash, "invalid fork choice update"}, no_payload_id};
        }

        if (!exec_engine_.is_ancestor(state.finalized_block_hash, head)) {
            return {{PayloadStatus::kInvalid, no_latest_valid_hash, "invalid fork choice state"}, no_payload_id};  // todo: return error code -38002
        }
        if (state.safe_block_hash != Hash() && !exec_engine_.is_ancestor(state.safe_block_hash, head)) {
            return {{PayloadStatus::kInvalid, no_latest_valid_hash, "invalid fork choice state"}, no_payload_id};  // todo: return error code -38002
        }

        PayloadId buildProcessId = 0;

        if (attributes) {
            // payload build process
            if (attributes->timestamp <= head_header->timestamp) {
                return {{PayloadStatus::kInvalid, no_latest_valid_hash, "invalid payload attributes"}, no_payload_id};  // todo: return error code -38003
                // in this case spec states that forkchoiceState update MUST NOT be rolled back
            }

            // buildProcessId = exec_engine_.build_payload(head_header_hash, attributes);  // todo: use timeout here
        }

        return {{PayloadStatus::kValid, state.head_block_hash}, buildProcessId};

    } catch (const PayloadValidationError& e) {
        log::Error("Sync") << "Error processing fork-choice: " << e.what();
        return {{PayloadStatus::kInvalid, no_latest_valid_hash, e.what()}, no_payload_id};
    } catch (const std::exception& e) {
        log::Error("Sync") << "Error processing fork-choice: " << e.what();
        return {{PayloadStatus::kInvalid, no_latest_valid_hash, e.what()}, no_payload_id};
    }
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

}  // namespace silkworm::chainsync