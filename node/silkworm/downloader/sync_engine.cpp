/*
Copyright 2022 The Silkworm Authors

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

#include "sync_engine.hpp"

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/measure.hpp>
#include <silkworm/downloader/messages/outbound_new_block.hpp>
#include <silkworm/downloader/messages/outbound_new_block_hashes.hpp>

namespace silkworm::chainsync {

SyncEngine::SyncEngine(BlockExchange& be, stagedsync::ExecutionEngine& ee)
    : block_exchange_{be},
      exec_engine_{ee},
      chain_fork_view_{ee.get_headers_head(), ee} {
    // BlockExchange need a starting point to start downloading from
    block_exchange_.initial_state(exec_engine_.get_last_headers(65536));
}

auto SyncEngine::forward_and_insert_blocks() -> NewHeight {
    using ResultQueue = BlockExchange::ResultQueue;

    ResultQueue& downloading = block_exchange_.result_queue();

    auto initial_header_head = exec_engine_.get_headers_head();
    block_exchange_.download_blocks(initial_header_head.number, BlockExchange::kTipOfTheChain);

    StopWatch timing;
    timing.start();
    RepeatedMeasure<BlockNum> downloaded_headers(initial_header_head.number);
    log::Info("Sync") << "Waiting for blocks... from=" << initial_header_head.number;

    while (!is_stopping() && !block_exchange_.in_sync()) {
        Blocks blocks;

        // wait for a batch of blocks
        bool present = downloading.timed_wait_and_pop(blocks, 100ms);
        if (!present) continue;

        Blocks announcements_to_do;

        // compute head of chain applying fork choice rule
        as_range::for_each(blocks, [this, &announcements_to_do](const auto& block) {
            block->td = chain_fork_view_.add(block->header);
            if (block->to_announce) announcements_to_do.push_back(block);
        });

        // insert blocks into database
        exec_engine_.insert_blocks(blocks);

        // send announcement to peers
        send_new_block_announcements(std::move(announcements_to_do));  // according to eth/67 they must be done here,
                                                                       // after simple header verification

        downloaded_headers.set(chain_fork_view_.head_height());
        log::Info("Sync") << "Downloading progress: +" << downloaded_headers.delta() << " blocks downloaded, "
                          << downloaded_headers.high_res_throughput<seconds_t>() << " headers/secs"
                          << ", last=" << downloaded_headers.get()
                          << ", tot.duration=" << StopWatch::format(timing.lap_duration());
    };

    log::Info("Sync") << "Downloading completed, last=" << chain_fork_view_.head_height();

    block_exchange_.stop_downloading();
    is_first_sync_ = false;

    return {.block_num = chain_fork_view_.head_height(), .hash = chain_fork_view_.head_hash()};
}

void SyncEngine::unwind(UnwindPoint) {
    // does nothing
}

void SyncEngine::execution_loop() {
    using namespace stagedsync;
    using ValidChain = ExecutionEngine::ValidChain;
    using ValidationError = ExecutionEngine::ValidationError;
    using InvalidChain = ExecutionEngine::InvalidChain;

    while (!is_stopping()) {
        NewHeight new_height = forward_and_insert_blocks();

        log::Info("Sync") << "Verifying chain, head=" << new_height.block_num;
        auto verification = exec_engine_.verify_chain(new_height.hash);

        if (std::holds_alternative<InvalidChain>(verification)) {
            auto invalid_chain = std::get<InvalidChain>(verification);
            log::Info("Sync") << "Invalid chain, unwinding down to=" << invalid_chain.unwind_point;

            unwind({invalid_chain.unwind_point});

            if (!invalid_chain.bad_headers.empty()) {
                update_bad_headers(std::move(invalid_chain.bad_headers));
            }

            log::Info("Sync") << "Notifying fork choice updated, head=" << invalid_chain.unwind_point;
            exec_engine_.notify_fork_choice_updated(invalid_chain.unwind_head);

            continue;
        } else if (std::holds_alternative<ValidationError>(verification)) {
            throw std::logic_error("Consensus, validation error");
        }

        auto valid_chain = std::get<ValidChain>(verification);
        log::Info("Sync") << "Valid chain, new head=" << valid_chain.current_point;

        if (valid_chain.current_point != new_height.block_num) {
            // ???
        }

        log::Info("Sync") << "Notifying fork choice updated, new head=" << new_height.block_num;
        exec_engine_.notify_fork_choice_updated(new_height.hash);

        if (!is_first_sync_)
            send_new_block_hash_announcements();  // according to eth/67 they must be done after a full block verification
    }
};

auto SyncEngine::update_bad_headers(std::set<Hash> bad_headers) -> std::shared_ptr<InternalMessage<void>> {
    auto message = std::make_shared<InternalMessage<void>>(
        [bads = std::move(bad_headers)](HeaderChain& hc, BodySequence&) { hc.add_bad_headers(bads); });

    block_exchange_.accept(message);

    return message;
}

// New block hash announcements propagation
void SyncEngine::send_new_block_hash_announcements() {
    auto message = std::make_shared<OutboundNewBlockHashes>(is_first_sync_);

    block_exchange_.accept(message);
}

// New block announcements propagation
void SyncEngine::send_new_block_announcements(Blocks&& blocks) {
    if (blocks.empty()) return;

    auto message = std::make_shared<OutboundNewBlock>(std::move(blocks), is_first_sync_);

    block_exchange_.accept(message);
}

}  // namespace silkworm::chainsync