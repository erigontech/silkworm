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

#include "execution_engine.hpp"

#include <set>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/db_utils.hpp>

namespace silkworm::stagedsync {

using namespace boost::asio;

ExecutionEngine::ExecutionEngine(asio::io_context& ctx, NodeSettings& ns, db::RWAccess dba)
    : io_context_{ctx},
      node_settings_{ns},
      main_chain_(ctx, ns, dba),
      block_cache_{kDefaultCacheSize} {
    // To initialize canonical_head_status_ & last_fork_choice_ we need to call verify_chain(). Enable?
    // verify_chain(canonical_chain_.current_head().hash);

    // At start-up we can let last_finalized_block_ point to the genesis block so to accept all forking points
    last_finalized_block_ = {0, ns.chain_config.value().genesis_hash.value()};
    last_fork_choice_ = last_finalized_block_;
}

void ExecutionEngine::open() {  // needed to circumvent mdbx threading model limitations
    main_chain_.open();
    block_progress_ = main_chain_.get_block_progress();
}

void ExecutionEngine::close() {
    main_chain_.close();
}

auto ExecutionEngine::block_progress() const -> BlockNum {
    return block_progress_;  // main_chain_.get_block_progress() or forks block progress
}

auto ExecutionEngine::last_fork_choice() const -> BlockId {
    return last_fork_choice_;
}

auto ExecutionEngine::last_finalized_block() const -> BlockId {
    return last_finalized_block_;
}

void ExecutionEngine::insert_blocks(const std::vector<std::shared_ptr<Block>>& blocks) {
    SILK_DEBUG << "ExecutionEngine: inserting " << blocks.size() << " blocks";
    if (blocks.empty()) return;

    for (const auto& block : blocks) {
        insert_block(block);
    }
}

bool ExecutionEngine::insert_block(const std::shared_ptr<Block> block) {
    Hash header_hash{block->header.hash()};

    if (block_cache_.get(header_hash)) return true;  // ignore repeated blocks
    block_cache_.put(header_hash, block);

    if (block_progress_ < block->header.number) block_progress_ = block->header.number;

    // if we are not tracking forks, just insert the block into the main chain
    if (!fork_tracking_active_) {
        main_chain_.insert_block(*block);  // BLOCKING
        return true;
    }

    // find attachment point at fork heads
    auto f = find_fork_to_extend(forks_, block->header);

    if (f != forks_.end()) {
        // the block extends a fork
        SILK_DEBUG << "ExecutionEngine: extending a fork";

        (*f)->extend_with(header_hash, *block);
    } else {
        // the block must be put to a new fork
        // (to avoid complicated code we ignore the case whether the attaching point is inside a current fork)

        auto forking_path = find_forking_point(block->header);
        if (!forking_path) return false;
        if (forking_path->forking_point.number < last_finalized_block().number) return false;  // ignore
        forking_path->blocks.push_back(block);

        SILK_DEBUG << "ExecutionEngine: creating new fork";

        forks_.push_back(main_chain_.fork(forking_path->forking_point));

        auto& new_fork = forks_.back();
        BlockId new_head = {.number = block->header.number, .hash = header_hash};
        new_fork->start_with(new_head, std::move(forking_path->blocks));
    }

    return true;
}

auto ExecutionEngine::find_forking_point(const BlockHeader& header) const -> std::optional<ForkingPath> {
    ForkingPath path;  // a path from the header to the first block of the main chain using parent-child relationship

    // search in cache till to the main chain
    path.forking_point = {.number = header.number - 1, .hash = header.parent_hash};
    while (path.forking_point.number > main_chain_.canonical_head().number) {
        auto parent = block_cache_.get_as_copy(path.forking_point.hash);  // parent is a pointer
        if (!parent) return {};                                           // not found
        path.blocks.push_front(*parent);                                  // in reverse order
        path.forking_point = {.number = (*parent)->header.number - 1, .hash = (*parent)->header.parent_hash};
    }

    // forking point is on main chain canonical head
    if (path.forking_point == main_chain_.canonical_head()) return {std::move(path)};

    // search remaining path on main chain
    if (main_chain_.is_canonical(path.forking_point)) return {std::move(path)};

    auto forking_point = main_chain_.find_forking_point(path.forking_point.hash);
    if (!forking_point) return {};  // not found

    return {std::move(path)};
}

auto ExecutionEngine::verify_chain(Hash head_block_hash) -> concurrency::AwaitableFuture<VerificationResult> {
    log::Info("ExecutionEngine") << "verifying chain " << head_block_hash.to_hex();

    if (last_fork_choice_.hash == head_block_hash) {
        SILK_DEBUG << "ExecutionEngine: chain " << head_block_hash.to_hex() << " already verified";
        concurrency::AwaitablePromise<VerificationResult> promise{io_context_};
        promise.set_value(ValidChain{last_fork_choice_});
        return promise.get_future();
    }

    if (!fork_tracking_active_) {
        auto verification = main_chain_.verify_chain(head_block_hash);  // BLOCKING
        concurrency::AwaitablePromise<VerificationResult> promise{io_context_};
        promise.set_value(std::move(verification));
        return promise.get_future();
    }

    auto fork = find_fork_by_head(forks_, head_block_hash);
    if (fork == forks_.end()) {
        SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at verification time";
        concurrency::AwaitablePromise<VerificationResult> promise{io_context_};
        promise.set_value(ValidationError{});
        return promise.get_future();
    }

    return (*fork)->verify_chain();
}

bool ExecutionEngine::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    log::Info("ExecutionEngine") << "updating fork choice to " << head_block_hash.to_hex();

    if (!fork_tracking_active_ || head_block_hash == last_fork_choice_.hash) {
        bool updated = main_chain_.notify_fork_choice_update(head_block_hash, finalized_block_hash);  // BLOCKING
        if (!updated) return false;

        last_fork_choice_ = main_chain_.canonical_head();
        fork_tracking_active_ = true;
    } else {
        // chose the fork with the given head
        auto f = find_fork_by_head(forks_, head_block_hash);
        if (f == forks_.end()) {
            SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at fork choice update time";
            return false;
        }
        std::unique_ptr<ExtendingFork> fork = std::move(*f);
        forks_.erase(f);
        discard_all_forks();  // remove all other forks

        // notify the fork of the update - we need to block here to restore the invariant
        auto updated = fork->notify_fork_choice_update(head_block_hash, finalized_block_hash).get();  // BLOCKING
        if (!updated) return false;

        last_fork_choice_ = fork->current_head();

        main_chain_.reintegrate_fork(*fork);  // BLOCKING

        fork->close();
    }

    if (finalized_block_hash) {
        auto finalized_header = main_chain_.get_header(*finalized_block_hash);  // BLOCKING
        ensure_invariant(finalized_header.has_value(), "finalized block not found in main chain");

        last_finalized_block_.hash = *finalized_block_hash;
        last_finalized_block_.number = finalized_header->number;
    }

    return true;
}

void ExecutionEngine::discard_all_forks() {
    // remove all forks except the given one from forks_
    // ensure a clean exit of all those forks that can be busy in a VerifyChain
    // method or something else; maybe use a sweeper thread

    for (auto it = forks_.begin(); it != forks_.end(); ++it) {
        (*it)->close();  // todo: maybe we should wait for the fork to close in another thread, a sweeper thread
    }
    forks_.clear();
}

// TO IMPLEMENT OR REWORK ---------------------------------------------------------------------------------------------

auto ExecutionEngine::get_header(Hash header_hash) const -> std::optional<BlockHeader> {
    // read from cache, then from main_chain_
    auto block = block_cache_.get_as_copy(header_hash);
    if (block) return (*block)->header;
    return main_chain_.get_header(header_hash);
}

auto ExecutionEngine::get_last_headers(BlockNum limit) const -> std::vector<BlockHeader> {
    ensure_invariant(!fork_tracking_active_, "actual get_last_headers() impl assume it is called only at beginning");
    // if fork_tracking_active_ is true, we should read blocks from cache where they are not ordered on block number

    return main_chain_.get_last_headers(limit);
}

auto ExecutionEngine::get_header_td(Hash h, std::optional<BlockNum> bn) const -> std::optional<TotalDifficulty> {
    ensure_invariant(!fork_tracking_active_, "actual get_header_td() impl assume it is called only at beginning");
    // if fork_tracking_active_ is true, we should read blocks from forks and recompute total difficulty but this
    // is a duty of the sync component
    if (bn) {
        return main_chain_.get_header_td(*bn, h);
    } else {
        return main_chain_.get_header_td(h);
    }
}

auto ExecutionEngine::get_body(Hash header_hash) const -> std::optional<BlockBody> {
    // read from cache, then from main_chain_
    auto block = block_cache_.get_as_copy(header_hash);
    if (block) return *(block.value().get());
    return main_chain_.get_body(header_hash);
}

auto ExecutionEngine::get_canonical_header(BlockNum bn) const -> std::optional<BlockHeader> {
    auto hash = main_chain_.get_canonical_hash(bn);
    if (!hash) return {};
    return main_chain_.get_header(*hash);
}

auto ExecutionEngine::get_canonical_body(BlockNum bn) const -> std::optional<BlockBody> {
    auto hash = main_chain_.get_canonical_hash(bn);
    if (!hash) return {};
    return main_chain_.get_body(*hash);
}

auto ExecutionEngine::get_block_number(Hash header_hash) const -> std::optional<BlockNum> {
    auto cached_block = block_cache_.get_as_copy(header_hash);
    if (cached_block) return (*cached_block)->header.number;
    auto header = main_chain_.get_header(header_hash);
    if (!header) return {};
    return header->number;
}

bool ExecutionEngine::is_canonical(Hash header_hash) const {
    auto header = main_chain_.get_header(header_hash);
    if (!header) return false;
    auto canonical_hash_at_same_height = main_chain_.get_canonical_hash(header->number);
    return (canonical_hash_at_same_height == header_hash);
}

}  // namespace silkworm::stagedsync
