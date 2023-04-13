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

static void ensure_invariant(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error("Execution invariant violation: " + message);
    }
}

ExecutionEngine::ExecutionEngine(NodeSettings& ns, db::RWAccess dba)
    : node_settings_{ns},
      db_access_{dba},
      tx_{db_access_.start_rw_tx()},
      main_chain_(ns, dba),
      block_cache_{kDefaultCacheSize} {
}

auto ExecutionEngine::last_fork_choice() -> std::optional<BlockId> {
    return last_fork_choice_;
}

void ExecutionEngine::insert_block(std::shared_ptr<Block> block) {
    Hash header_hash{block->header.hash()};

    if (block_cache_.get(header_hash)) return;  // ignore repeated blocks
    block_cache_.put(header_hash, block);

    // if we are not tracking forks, just insert the block into the main chain
    if (!fork_tracking_active_) {
        main_chain_.insert_block(*block);
        return;
    }

    // find attachment point at fork heads
    auto f = find_fork_to_extend(forks_, block->header);

    if (f != forks_.end()) {
        // the block extends a fork
        SILK_DEBUG << "ExecutionEngine: extending a fork";
        f->extend_with(*block);
        return;
    }
    else {
        // the block must be put to a new fork
        // (to avoid complicated code we ignore the case whether the attaching point is inside a current fork)

        auto forking_point = find_forking_point(block->header);
        if (!forking_point) return;  // ignore or raise exception?
        if (forking_point->number < main_chain_.last_fork_choice().number) return;  // ignore | todo: check if this is correct

        SILK_DEBUG << "ExecutionEngine: creating new fork";

        auto& new_fork = forks_.emplace_back(*forking_point, node_settings_, main_chain_);
        // if (new_fork.current_head().number < main_chain_.last_fork_choice().number) new_fork->reduce_down_to(*forking_point);
        fill_fork(new_fork, block_cache_, BlockId{block->header.number - 1, block->header.parent_hash});
        new_fork.extend_with(*block);
    }

}

bool ExecutionEngine::is_viable_fork(const BlockHeader& head_header) const {
    auto forking_point = main_chain_.find_forking_point(head_header);
    if (!forking_point) return false;
    return main_chain_.last_fork_choice().number < forking_point->number;  // todo: check if this is correct
}

std::optional<BlockId> find_forking_point(const BlockHeader& header) const {
    // todo: implement using block_cache_ and main_chain_
    return {};
}

void ExecutionEngine::insert_blocks(std::vector<std::shared_ptr<Block>>& blocks) {
    SILK_DEBUG << "ExecutionEngine: inserting " << blocks.size() << " blocks";
    if (blocks.empty()) return;

    as_range::for_each(blocks, [&, this](const auto& block) {
        insert_block(block);
    });
}

auto ExecutionEngine::verify_chain(Hash head_block_hash) -> VerificationResult {
    SILK_DEBUG << "ExecutionEngine: verifying chain " << head_block_hash.to_hex();

    if (!fork_tracking_active_) return main_chain_.verify_chain(head_block_hash);

    auto f = find_fork_by_head(forks_, head_block_hash);
    if (f == forks_.end()) {
        SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at verification time";
        return ValidationError{};
    }

    Fork& fork = *f;

    return fork.verify_chain();
}

bool ExecutionEngine::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    SILK_DEBUG << "ExecutionEngine: updating fork choice to " << head_block_hash.to_hex();

    if (!fork_tracking_active_) {
        bool updated = main_chain_.notify_fork_choice_update(head_block_hash, finalized_block_hash);
        if (!updated) return false;

        last_fork_choice_ = main_chain_.canonical_head();
        if (finalized_block_hash) last_finalized_block_ = *finalized_block_hash;
    } else {
        // chose the fork with the given head
        auto f = find_fork_by_head(forks_, head_block_hash);
        if (f == forks_.end()) {
            SILK_WARN << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at fork choice update time";
            return false;
        }
        Fork& chosen_fork = *f;

        // notify the fork of the update
        bool updated = chosen_fork.notify_fork_choice_update(head_block_hash, finalized_block_hash);
        if (!updated) return false;

        last_fork_choice_ = chosen_fork.current_head();
        if (finalized_block_hash) last_finalized_block_ = *finalized_block_hash;

        consolidate_forks();  // remove side forks, extend main chain with the chosen fork
    }

    fork_tracking_active_ = true;
    is_first_sync_ = false;

    return true;
}

void ExecutionEngine::consolidate_forks() {
}

}  // namespace silkworm::stagedsync
