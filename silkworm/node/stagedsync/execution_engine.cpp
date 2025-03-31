// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "execution_engine.hpp"

#include <algorithm>
#include <future>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::stagedsync {

using namespace boost::asio;
using execution::api::ValidationError;
using execution::api::ValidChain;
using execution::api::VerificationResult;

ExecutionEngine::ExecutionEngine(
    std::optional<boost::asio::any_io_executor> executor,
    NodeSettings& ns,
    db::DataModelFactory data_model_factory,
    std::optional<TimerFactory> log_timer_factory,
    StageContainerFactory stages_factory,
    datastore::kvdb::RWAccess dba)
    : context_pool_{executor ? std::unique_ptr<concurrency::ContextPool<>>{} : std::make_unique<concurrency::ContextPool<>>(1)},
      executor_{executor ? std::move(*executor) : context_pool_->any_executor()},
      node_settings_{ns},
      main_chain_{
          executor_,
          ns,
          std::move(data_model_factory),
          std::move(log_timer_factory),
          std::move(stages_factory),
          std::move(dba),
      },
      block_cache_{kDefaultCacheSize} {}

void ExecutionEngine::open() {  // needed to circumvent mdbx threading model limitations
    if (context_pool_) context_pool_->start();
    main_chain_.open();
    last_finalized_block_ = main_chain_.last_finalized_head();
    last_fork_choice_ = main_chain_.last_chosen_head();
    block_progress_ = main_chain_.get_block_progress();
}

void ExecutionEngine::close() {
    main_chain_.close();
    context_pool_.reset();
}

BlockNum ExecutionEngine::block_progress() const {
    return block_progress_;  // main_chain_.get_block_progress() or forks block progress
}

BlockId ExecutionEngine::last_fork_choice() const {
    return last_fork_choice_;
}

BlockId ExecutionEngine::last_finalized_block() const {
    return last_finalized_block_;
}

BlockId ExecutionEngine::last_safe_block() const {
    return last_safe_block_;
}

BlockNum ExecutionEngine::max_frozen_block_num() const {
    return main_chain_.max_frozen_block_num();
}

void ExecutionEngine::insert_blocks(const std::vector<std::shared_ptr<Block>>& blocks) {
    SILK_DEBUG << "ExecutionEngine: inserting " << blocks.size() << " blocks";
    if (blocks.empty()) return;

    for (const auto& block : blocks) {
        insert_block(block);
    }
}

bool ExecutionEngine::insert_block(const std::shared_ptr<Block>& block) {
    Hash header_hash{block->header.hash()};

    if (block_cache_.get(header_hash)) return true;  // ignore repeated blocks
    block_cache_.put(header_hash, block);

    block_progress_ = std::max(block_progress_, block->header.number);

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
        if (forking_path->forking_point.block_num < last_finalized_block().block_num) return false;  // ignore
        forking_path->blocks.push_back(block);

        SILK_DEBUG << "ExecutionEngine: creating new fork";

        forks_.push_back(main_chain_.fork(forking_path->forking_point));

        auto& new_fork = forks_.back();
        BlockId new_head = {.block_num = block->header.number, .hash = header_hash};
        new_fork->start_with(new_head, std::move(forking_path->blocks));
    }

    return true;
}

std::optional<ExecutionEngine::ForkingPath> ExecutionEngine::find_forking_point(const BlockHeader& header) const {
    ForkingPath path;  // a path from the header to the first block of the main chain using parent-child relationship

    // search in cache till to the main chain
    path.forking_point = {.block_num = header.number - 1, .hash = header.parent_hash};
    while (path.forking_point.block_num > main_chain_.last_chosen_head().block_num) {
        auto parent = block_cache_.get_as_copy(path.forking_point.hash);  // parent is a pointer
        if (!parent) return {};                                           // not found
        path.blocks.push_front(*parent);                                  // in reverse order
        path.forking_point = {.block_num = (*parent)->header.number - 1, .hash = (*parent)->header.parent_hash};
    }

    // forking point is on main chain canonical head
    if (path.forking_point == main_chain_.last_chosen_head()) return {std::move(path)};

    // search remaining path on main chain
    if (main_chain_.is_finalized_canonical(path.forking_point)) return {std::move(path)};

    auto forking_point = main_chain_.find_forking_point(path.forking_point.hash);
    if (!forking_point) return {};  // not found

    return {std::move(path)};
}

VerificationResult ExecutionEngine::verify_chain_no_fork_tracking(Hash head_block_hash) {
    SILK_INFO_M("ExecutionEngine") << "verifying chain " << head_block_hash.to_hex();

    SILKWORM_ASSERT(!fork_tracking_active_);

    if (last_fork_choice_.hash == head_block_hash) {
        SILK_DEBUG << "ExecutionEngine: chain " << head_block_hash.to_hex() << " already verified";
        return ValidChain{last_fork_choice_};
    }

    return main_chain_.verify_chain(head_block_hash);
}

Task<VerificationResult> ExecutionEngine::verify_chain(Hash head_block_hash) {
    SILK_INFO_M("ExecutionEngine") << "verifying chain " << head_block_hash.to_hex();

    if (last_fork_choice_.hash == head_block_hash) {
        SILK_DEBUG << "ExecutionEngine: chain " << head_block_hash.to_hex() << " already verified";
        co_return ValidChain{last_fork_choice_};
    }

    if (!fork_tracking_active_) {
        auto verification = main_chain_.verify_chain(head_block_hash);  // BLOCKING
        co_return verification;
    }

    auto fork = find_fork_by_head(forks_, head_block_hash);
    if (fork == forks_.end()) {
        if (main_chain_.is_finalized_canonical(head_block_hash)) {
            SILK_DEBUG << "ExecutionEngine: chain " << head_block_hash.to_hex() << " already verified";
            co_return ValidChain{last_fork_choice_};
        } else {
            SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at verification time";
            co_return ValidationError{};
        }
    }

    auto verify_chain_future = (*fork)->verify_chain();
    co_return (co_await verify_chain_future.get());
}

bool ExecutionEngine::notify_fork_choice_update(Hash head_block_hash,
                                                std::optional<Hash> finalized_block_hash,
                                                std::optional<Hash> safe_block_hash) {
    SILK_INFO_M("ExecutionEngine") << "updating fork choice to " << head_block_hash.to_hex();

    if (!fork_tracking_active_ || head_block_hash == last_fork_choice_.hash) {
        bool updated = main_chain_.notify_fork_choice_update(head_block_hash, finalized_block_hash);  // BLOCKING
        if (!updated) return false;

        last_fork_choice_ = main_chain_.last_chosen_head();
        if (head_block_hash == main_chain_.current_head().hash && node_settings_.parallel_fork_tracking_enabled) {
            SILK_INFO_M("ExecutionEngine") << "activate parallel fork tracking at head " << head_block_hash.to_hex();
            fork_tracking_active_ = true;
        }
    } else {
        // chose the fork with the given head
        auto f = find_fork_by_head(forks_, head_block_hash);

        if (f == forks_.end()) {
            if (main_chain_.is_finalized_canonical(head_block_hash)) {
                SILK_DEBUG << "ExecutionEngine: chain " << head_block_hash.to_hex() << " already chosen";
                return true;
            }
            SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at fork choice update time";
            return false;
        }

        // notify the fork of the update - we need to block here to restore the invariant
        auto fork_choice_aw_future = (*f)->fork_choice(head_block_hash, finalized_block_hash, safe_block_hash);
        std::future<bool> fork_choice_future = concurrency::spawn_future(executor_, fork_choice_aw_future.get());
        bool updated = fork_choice_future.get();  // BLOCKING
        if (!updated) return false;

        std::unique_ptr<ExtendingFork> fork = std::move(*f);
        forks_.erase(f);
        discard_all_forks();  // remove all other forks

        last_fork_choice_ = fork->current_head();

        main_chain_.reintegrate_fork(*fork);  // BLOCKING

        fork->close();
    }

    if (finalized_block_hash) {
        const auto finalized_header = main_chain_.get_header(*finalized_block_hash);
        ensure_invariant(finalized_header.has_value(), "finalized block not found in main chain");

        last_finalized_block_ = {finalized_header->number, *finalized_block_hash};
    }
    if (safe_block_hash) {
        const auto safe_header = main_chain_.get_header(*safe_block_hash);
        ensure_invariant(safe_header.has_value(), "safe block not found in main chain");

        last_safe_block_ = {safe_header->number, *safe_block_hash};
    }

    return true;
}

void ExecutionEngine::discard_all_forks() {
    // remove all forks except the given one from forks_
    // ensure a clean exit of all those forks that can be busy in a VerifyChain
    // method or something else; maybe use a sweeper thread

    for (auto& fork : forks_) {
        fork->close();  // todo: maybe we should wait for the fork to close in another thread, a sweeper thread
    }
    forks_.clear();
}

// TO IMPLEMENT OR REWORK ---------------------------------------------------------------------------------------------

std::optional<BlockHeader> ExecutionEngine::get_header(Hash header_hash) const {
    // read from cache, then from main_chain_
    auto block = block_cache_.get_as_copy(header_hash);
    if (block) return (*block)->header;
    return main_chain_.get_header(header_hash);
}

std::optional<BlockHeader> ExecutionEngine::get_header(BlockNum block_num, Hash hash) const {
    // read from cache, then from main_chain_
    auto block = block_cache_.get_as_copy(hash);
    if (block) return (*block)->header;
    return main_chain_.get_header(block_num, hash);
}

std::vector<BlockHeader> ExecutionEngine::get_last_headers(uint64_t limit) const {
    ensure_invariant(!fork_tracking_active_, "actual get_last_headers() impl assume it is called only at beginning");
    // if fork_tracking_active_ is true, we should read blocks from cache where they are not ordered on block number

    return main_chain_.get_last_headers(limit);
}

std::optional<TotalDifficulty> ExecutionEngine::get_header_td(Hash h, std::optional<BlockNum> block_num) const {
    ensure_invariant(!fork_tracking_active_, "actual get_header_td() impl assume it is called only at beginning");
    // if fork_tracking_active_ is true, we should read blocks from forks and recompute total difficulty but this
    // is a duty of the sync component
    if (block_num) {
        return main_chain_.get_header_td(*block_num, h);
    }
    return main_chain_.get_header_td(h);
}

std::optional<BlockBody> ExecutionEngine::get_body(Hash header_hash) const {
    // read from cache, then from main_chain_
    auto block = block_cache_.get_as_copy(header_hash);
    if (block) return *(block.value().get());
    return main_chain_.get_body(header_hash);
}

std::optional<BlockHeader> ExecutionEngine::get_canonical_header(BlockNum block_num) const {
    auto hash = main_chain_.get_finalized_canonical_hash(block_num);
    if (!hash) return {};
    return main_chain_.get_header(*hash);
}

std::optional<Hash> ExecutionEngine::get_canonical_hash(BlockNum block_num) const {
    return main_chain_.get_finalized_canonical_hash(block_num);
}

std::optional<BlockBody> ExecutionEngine::get_canonical_body(BlockNum block_num) const {
    auto hash = main_chain_.get_finalized_canonical_hash(block_num);
    if (!hash) return {};
    return main_chain_.get_body(*hash);
}

std::optional<BlockNum> ExecutionEngine::get_block_num(Hash header_hash) const {
    auto cached_block = block_cache_.get_as_copy(header_hash);
    if (cached_block) return (*cached_block)->header.number;
    return main_chain_.get_block_num(header_hash);
}

bool ExecutionEngine::is_canonical(Hash header_hash) const {
    return main_chain_.is_finalized_canonical(header_hash);
}

datastore::StageScheduler& ExecutionEngine::stage_scheduler() const {
    return main_chain_.stage_scheduler();
}

}  // namespace silkworm::stagedsync
