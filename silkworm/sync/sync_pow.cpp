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

#include "sync_pow.hpp"

#include <algorithm>

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/common/measure.hpp>
#include <silkworm/infra/common/stopwatch.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>
#include <silkworm/sync/messages/outbound_new_block.hpp>
#include <silkworm/sync/messages/outbound_new_block_hashes.hpp>

namespace silkworm::chainsync {

using concurrency::spawn_and_wait;

PoWSync::PoWSync(BlockExchange& block_exchange, execution::api::Client& exec_engine)
    : ChainSync(block_exchange, exec_engine) {}

Task<void> PoWSync::async_run() {
    return ActiveComponent::async_run("pow-sync-ex");
}

PoWSync::NewHeight PoWSync::resume() {  // find the point (head) where we left off
    BlockId head{};

    // BlockExchange need a bunch of previous headers to attach the new ones
    auto last_headers = spawn_and_wait(io_context_, exec_engine_->get_last_headers(1000));
    block_exchange_.initial_state(last_headers);

    // We calculate a provisional head based on the previous headers
    std::ranges::for_each(last_headers, [&, this](const auto& header) {
        auto hash = header.hash();
        auto td = spawn_and_wait(io_context_, exec_engine_->get_td(hash));
        chain_fork_view_.add(header, *td);  // add to cache & compute a new canonical head
    });

    // Now we can resume the sync from the canonical head
    const auto last_fcu = spawn_and_wait(io_context_, exec_engine_->get_fork_choice());  // previously was get_canonical_head()
    const auto block_progress = spawn_and_wait(io_context_, exec_engine_->block_progress());

    const auto last_fcu_number = spawn_and_wait(io_context_, exec_engine_->get_header_hash_number(last_fcu.head_block_hash));
    if (!last_fcu_number) return head;
    ensure_invariant(*last_fcu_number <= block_progress, "canonical head beyond block progress");

    if (block_progress == *last_fcu_number) {
        // If FCU and header progress match than we have the actual canonical, we only need to do a forward sync...
        const auto total_difficulty{chain_fork_view_.get_total_difficulty(last_fcu.head_block_hash)};
        if (!total_difficulty) return head;
        ChainHead fcu_as_head{*last_fcu_number, last_fcu.head_block_hash, *total_difficulty};
        ensure_invariant(fcu_as_head == chain_fork_view_.head(), "last FCU misaligned with canonical head");
        chain_fork_view_.reset_head(fcu_as_head);
        head = to_BlockId(fcu_as_head);
    } else {
        // ... else we use the head computed parsing the last N headers
        head = to_BlockId(chain_fork_view_.head());
    }

    return head;
}

PoWSync::NewHeight PoWSync::forward_and_insert_blocks() {
    using namespace std::chrono_literals;
    using ResultQueue = BlockExchange::ResultQueue;

    ResultQueue& downloading_queue = block_exchange_.result_queue();

    auto initial_block_progress = spawn_and_wait(io_context_, exec_engine_->block_progress());
    auto block_progress = initial_block_progress;

    block_exchange_.download_blocks(initial_block_progress, BlockExchange::Target_Tracking::kByAnnouncements);

    StopWatch timing(StopWatch::kStart);
    RepeatedMeasure<BlockNum> downloaded_headers(initial_block_progress);
    log::Info("Sync") << "Waiting for blocks... from=" << initial_block_progress;

    while (!is_stopping() &&
           !(block_exchange_.in_sync() && block_progress == block_exchange_.current_height())) {
        Blocks blocks;

        // wait for a batch of blocks
        bool present = downloading_queue.timed_wait_and_pop(blocks, 100ms);
        if (!present) continue;

        Blocks announcements_to_do;

        // compute head of chain applying fork choice rule
        std::ranges::for_each(blocks, [&, this](const auto& block) {
            block->td = chain_fork_view_.add(block->header);
            block_progress = std::max(block_progress, block->header.number);
            if (block->to_announce) announcements_to_do.push_back(block);
        });

        // Insert blocks into database
        const auto insert_result{spawn_and_wait(io_context_, exec_engine_->insert_blocks(to_plain_blocks(blocks)))};
        if (!insert_result) {
            log::Error("Sync") << "Cannot insert " << blocks.size() << " blocks, error=" << insert_result.status;
            continue;
        }

        // Send announcement to peers
        send_new_block_announcements(std::move(announcements_to_do));  // according to eth/67 they must be done here,
                                                                       // after simple header verification

        downloaded_headers.set(block_progress);
        log::Info("Sync") << "Downloading progress: +" << downloaded_headers.delta() << " blocks downloaded, "
                          << downloaded_headers.high_res_throughput<seconds_t>() << " headers/secs"
                          << ", last=" << downloaded_headers.get()
                          << ", head=" << chain_fork_view_.head_height()
                          << ", lap.duration=" << StopWatch::format(timing.since_start());
    }

    block_exchange_.stop_downloading();

    auto [tp, duration] = timing.stop();
    log::Info("Sync") << "Downloading completed, last=" << block_progress
                      << ", head=" << chain_fork_view_.head_height()
                      << ", tot.duration=" << StopWatch::format(duration);

    return {.number = chain_fork_view_.head_height(), .hash = chain_fork_view_.head_hash()};
}

void PoWSync::unwind(UnwindPoint, std::optional<Hash>) {
    // does nothing
}

void PoWSync::execution_loop() {
    using namespace execution;
    bool is_starting_up = true;

    // Main cycle
    while (!is_stopping()) {
        // Resume from previous run or download new blocks
        NewHeight new_height = is_starting_up
                                   ? resume()                      // resuming, the following verify_chain is needed to check all stages
                                   : forward_and_insert_blocks();  // downloads new blocks and inserts them into the db
        if (new_height.number == 0) {
            // When starting from empty db there is no chain to verify, so go on downloading new blocks
            is_starting_up = false;
            continue;
        }

        // Verify the new section of the chain
        log::Info("Sync") << "Verifying chain, head=(" << new_height.number << ", " << to_hex(new_height.hash) << ")";
        const auto verification = spawn_and_wait(io_context_, exec_engine_->validate_chain(new_height));  // BLOCKING

        if (std::holds_alternative<execution::api::ValidChain>(verification)) {
            auto valid_chain = std::get<execution::api::ValidChain>(verification);

            log::Info("Sync") << "Valid chain, new head=" << valid_chain.current_head.hash;

            // If it is valid, do nothing, only check invariant
            ensure_invariant(valid_chain.current_head.hash == new_height.hash, "invalid validate_chain result");

            // Notify the fork choice
            log::Info("Sync") << "Notifying fork choice updated, new head=" << new_height.number;
            spawn_and_wait(io_context_, exec_engine_->update_fork_choice({new_height.hash}));

            send_new_block_hash_announcements();  // according to eth/67 they must be done after a full block verification

        } else if (std::holds_alternative<execution::api::InvalidChain>(verification)) {
            auto invalid_chain = std::get<execution::api::InvalidChain>(verification);

            const auto latest_valid_height = spawn_and_wait(io_context_, exec_engine_->get_header_hash_number(invalid_chain.unwind_point.hash));
            ensure_invariant(latest_valid_height.has_value(), "wrong latest_valid_head");

            log::Info("Sync") << "Invalid chain, unwinding down to=" << *latest_valid_height;

            // If it is not valid, unwind the chain
            unwind({*latest_valid_height, invalid_chain.unwind_point.hash}, invalid_chain.bad_block);

            if (!invalid_chain.bad_headers.empty()) {
                update_bad_headers(std::move(invalid_chain.bad_headers));
            }

            // Notify the fork choice
            log::Info("Sync") << "Notifying fork choice updated, head=" << to_hex(invalid_chain.unwind_point.hash);
            spawn_and_wait(io_context_, exec_engine_->update_fork_choice({invalid_chain.unwind_point.hash}));

        } else if (std::holds_alternative<execution::api::ValidationError>(verification)) {
            // If it returned a validation error, raise an exception
            const auto validation_error = std::get<execution::api::ValidationError>(verification);
            throw std::logic_error("Consensus validation error: last point=" + validation_error.latest_valid_head.hash.to_hex() +
                                   ", error=" + validation_error.error);

        } else {
            throw std::logic_error("Consensus, unknown error");
        }

        is_first_sync_ = is_starting_up;
        is_starting_up = false;
    }
}

std::shared_ptr<InternalMessage<void>> PoWSync::update_bad_headers(std::set<Hash> bad_headers) {
    auto message = std::make_shared<InternalMessage<void>>(
        [bad_headers = std::move(bad_headers)](HeaderChain& hc, BodySequence&) { hc.add_bad_headers(bad_headers); });

    block_exchange_.accept(message);

    return message;
}

// New block hash announcements propagation
void PoWSync::send_new_block_hash_announcements() {
    auto message = std::make_shared<OutboundNewBlockHashes>(is_first_sync_);

    block_exchange_.accept(message);
}

// New block announcements propagation
void PoWSync::send_new_block_announcements(Blocks&& blocks) {
    if (blocks.empty()) return;

    auto message = std::make_shared<OutboundNewBlock>(std::move(blocks), is_first_sync_);

    block_exchange_.accept(message);
}

}  // namespace silkworm::chainsync