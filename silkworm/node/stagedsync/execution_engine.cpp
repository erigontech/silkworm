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
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/db_utils.hpp>

namespace silkworm::stagedsync {

using namespace boost::asio;

static void ensure_invariant(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error("Execution invariant violation: " + message);
    }
}

ExecutionEngine::ExecutionEngine(asio::io_context& ctx, NodeSettings& ns, db::RWAccess dba)
    : io_context_{ctx},
      node_settings_{ns},
      db_access_{dba},
      tx_{db_access_.start_rw_tx()},
      main_chain_(ctx, ns, dba),
      block_cache_{kDefaultCacheSize} {
    // To initialize canonical_head_status_ & last_fork_choice_ we need to call verify_chain(). Enable?
    // verify_chain(canonical_chain_.current_head().hash);

    // At start-up we can let last_finalized_block_ point to the genesis block so to accept all forking points
    last_finalized_block_ = {0, ns.chain_config.value().genesis_hash.value()};

    block_progress_ = main_chain_.get_block_progress();

    tx_.commit_and_stop();
}

void ExecutionEngine::open() {  // needed to circumvent mdbx threading model limitations
    tx_.reopen(*db_access_);
    main_chain_.open();
}

auto ExecutionEngine::last_fork_choice() const -> std::optional<BlockId> {
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

void ExecutionEngine::insert_block(const std::shared_ptr<Block> block) {
    Hash header_hash{block->header.hash()};

    if (block_cache_.get(header_hash)) return;  // ignore repeated blocks
    block_cache_.put(header_hash, block);

    if (block_progress_ < block->header.number) block_progress_ = block->header.number;

    // if we are not tracking forks, just insert the block into the main chain
    if (!fork_tracking_active_) {
        main_chain_.insert_block(*block);  // BLOCKING
        return;
    }

    // find attachment point at fork heads
    auto f = find_fork_to_extend(forks_, block->header);

    if (f != forks_.end()) {
        // the block extends a fork
        SILK_DEBUG << "ExecutionEngine: extending a fork";

        f->extend_with(header_hash, *block);

    } else {
        // the block must be put to a new fork
        // (to avoid complicated code we ignore the case whether the attaching point is inside a current fork)

        auto forking_path = find_forking_point(block->header);
        if (!forking_path) return;
        if (forking_path->forking_point.number < last_finalized_block().number) return;  // ignore
        forking_path->blocks.push_back(block);

        SILK_DEBUG << "ExecutionEngine: creating new fork";

        forks_.push_back(main_chain_.fork(forking_path->forking_point));

        auto& new_fork = forks_.back();
        BlockId new_head = {.number = block->header.number, .hash = header_hash};
        new_fork.start_with(new_head, std::move(forking_path->blocks));
    }
}

auto ExecutionEngine::find_forking_point(const BlockHeader& header) const -> std::optional<ForkingPath> {
    ForkingPath path;

    // search in cache
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
    auto forking_point = main_chain_.find_forking_point(path.forking_point.hash);
    if (!forking_point) return {};  // not found

    return {std::move(path)};
}

auto ExecutionEngine::verify_chain(Hash head_block_hash) -> concurrency::AwaitableFuture<VerificationResult> {
    SILK_DEBUG << "ExecutionEngine: verifying chain " << head_block_hash.to_hex();

    if (!fork_tracking_active_) {
        auto verification = main_chain_.verify_chain(head_block_hash);  // BLOCKING
        concurrency::AwaitablePromise<VerificationResult> promise{io_context_};
        promise.set_value(std::move(verification));
        return promise.get_future();
    }

    auto f = find_fork_by_head(forks_, head_block_hash);
    if (f == forks_.end()) {
        SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at verification time";
        concurrency::AwaitablePromise<VerificationResult> promise{io_context_};
        promise.set_value(ValidationError{});
        return promise.get_future();
    }

    ExtendingFork& fork = *f;

    return fork.verify_chain();
}

bool ExecutionEngine::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    SILK_DEBUG << "ExecutionEngine: updating fork choice to " << head_block_hash.to_hex();

    if (!fork_tracking_active_) {
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
        ExtendingFork& fork = *f;

        discard_all_forks_except(fork);  // remove all other forks

        // notify the fork of the update - we need to block here to restore the invariant
        auto updated = fork.notify_fork_choice_update(head_block_hash, finalized_block_hash).get();  // BLOCKING
        if (!updated) return false;

        last_fork_choice_ = fork.current_head();

        main_chain_.reintegrate_fork(std::move(fork));  // BLOCKING
    }

    if (finalized_block_hash) {
        auto finalized_header = main_chain_.get_header(*finalized_block_hash);  // BLOCKING
        ensure_invariant(finalized_header.has_value(), "finalized block not found in main chain");

        last_finalized_block_.hash = *finalized_block_hash;
        last_finalized_block_.number = finalized_header->number;
    }

    return true;
}

void ExecutionEngine::discard_all_forks_except(ExtendingFork&) {
    throw std::runtime_error("not implemented");
    // remove all forks except the given one from forks_
    // ensure a clean exit of all those forks that can be busy in a VerifyChain
    // method or something else; maybe use a sweeper thread
}

// TO IMPLEMENT OR REWORK ---------------------------------------------------------------------------------------------

auto ExecutionEngine::get_block_progress() const -> BlockNum {
    return block_progress_;  // main_chain_.get_block_progress() or forks block progress
}

auto ExecutionEngine::get_header([[maybe_unused]] Hash header_hash) const -> std::optional<BlockHeader> {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::get_header([[maybe_unused]] BlockNum header_height, [[maybe_unused]] Hash header_hash) const -> std::optional<BlockHeader> {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::get_canonical_hash([[maybe_unused]] BlockNum height) const -> std::optional<Hash> {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::get_canonical_head() const -> BlockId {
    return main_chain_.canonical_head();
}

auto ExecutionEngine::get_header_td([[maybe_unused]] BlockNum header_height, [[maybe_unused]] Hash header_hash) const -> std::optional<TotalDifficulty> {
    // implement...
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::get_body([[maybe_unused]] Hash header_hash) const -> std::optional<BlockBody> {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::get_last_headers([[maybe_unused]] BlockNum limit) const -> std::vector<BlockHeader> {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::is_ancestor([[maybe_unused]] BlockId supposed_parent, [[maybe_unused]] BlockId block) const -> bool {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::extends_last_fork_choice([[maybe_unused]] BlockNum height, [[maybe_unused]] Hash hash) const -> bool {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

auto ExecutionEngine::extends([[maybe_unused]] BlockId block, [[maybe_unused]] BlockId supposed_parent) const -> bool {
    // read from cache, then from main_chain_
    throw std::runtime_error("not implemented");
    return {};
}

}  // namespace silkworm::stagedsync
