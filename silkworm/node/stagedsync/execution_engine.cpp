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
      main_chain_(ns, dba)
{
}

auto ExecutionEngine::last_fork_choice() -> BlockId {
    return last_fork_choice_;
}

void ExecutionEngine::insert_block(const Block& block) {
    Hash header_hash{block.header.hash()};

    // find attachment point at fork heads
    auto f = best_fork_to_extend(forks_, block.header);

    if (f != forks_.end()) {
        SILK_TRACE << "ExecutionEngine: extending a fork";
        f->extend_with(block);
        return;
    }

    // find attachment point within fork blocks
    f = best_fork_to_branch(forks_, block.header, header_hash);

    if (f != forks_.end()) {
        SILK_TRACE << "ExecutionEngine: branching a fork";
        forks_.emplace_back(f->branch_at(block, header_hash));
        return;
    }

    // create a new fork from the past

    if (acceptable_fork(block.header)) {
        SILK_TRACE << "ExecutionEngine: creating new fork";
        auto f = forks_.emplace_back(
            Fork({block.header.number - 1, block.header.parent_hash},
                 node_settings_, db_access_));
        f.extend_with(block);
    }
}

bool ExecutionEngine::acceptable_fork(const BlockHeader& head_header) const {
    auto forking_point = main_chain_.find_forking_point(head_header);
    if (!forking_point) return false;
    return main_chain_.last_fork_choice().number < forking_point->number;     // todo: check if this is correct
}

void ExecutionEngine::insert_blocks(std::vector<std::shared_ptr<Block>>& blocks) {
    SILK_TRACE << "ExecutionEngine: inserting " << blocks.size() << " blocks";
    if (blocks.empty()) return;

    as_range::for_each(blocks, [&, this](const auto& block) {
        insert_block(*block);
    });

    if (is_first_sync_) tx_.commit_and_renew();
}

auto ExecutionEngine::verify_chain(Hash head_block_hash) -> VerificationResult {
    SILK_TRACE << "ExecutionEngine: verifying chain " << head_block_hash.to_hex();

    auto f = std::find_if(forks_.begin(), forks_.end(), [&](const auto& fork) {
        return fork.current_head().hash == head_block_hash;
    });

    if (!f) {
        SILK_TRACE << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at verification time";
        return ValidationError{root};
    }

    Fork& fork = *f;

    return fork.verify_chain(head_block_hash);
}

bool ExecutionEngine::notify_fork_choice_update(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    auto f = find_fork_with_head(forks_, head_block_hash);

    if (f == forks_.end()) {
        SILK_TRACE << "ExecutionEngine: chain " << head_block_hash.to_hex() << " not found at fork choice update time";
        return false;
    }

    Fork& fork = *f;

    bool updated = fork.notify_fork_choice_update(head_block_hash, finalized_block_hash);

    if (!updated) return false;

    consolidate_forks();

    last_fork_choice_ = head_block_hash;

    is_first_sync_ = false;

    return true;
}

}  // namespace silkworm::stagedsync
