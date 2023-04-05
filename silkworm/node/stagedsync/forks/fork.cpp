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

#include "fork.hpp"

#include <set>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/db_utils.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

namespace silkworm::stagedsync {

static void ensure_invariant(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error("Fork invariant violation: " + message);
    }
}

Fork::Fork(BlockId forking_point, NodeSettings& ns, const db::RWAccess dba)
    : node_settings_{ns},
      db_access_{dba},
      tx_{db_access_.start_rw_tx()},
      pipeline_{&ns},
      canonical_chain_(tx_) {
    ensure_invariant(canonical_chain_.initial_head() == forking_point,
                     "forking point must be the current canonical head");
    current_head_ = forking_point;
}

BlockId Fork::current_head() const {
    return current_head_;
}

BlockId Fork::last_verified_head() const {
    return last_verified_head_;
}

VerificationResult Fork::last_head_status() const {
    return last_head_status_;
}

bool Fork::extends_head(const BlockHeader& header) const {
    return current_head().hash == header.parent_hash;
}

BlockId Fork::last_fork_choice() const {
    return last_fork_choice_;
}

std::optional<BlockNum> Fork::find_block(Hash header_hash) const {
    auto curr_height = current_head().number;
    while (curr_height > canonical_chain_.initial_head().number) {
        auto canonical_hash = canonical_chain_.get_hash(curr_height);
        ensure_invariant(canonical_hash.has_value(), "canonical chain must be complete");
        if (canonical_hash == header_hash) {
            return curr_height;
        }
        curr_height--;
    }
    return std::nullopt;
}

std::optional<BlockId> Fork::find_attachment_point(const BlockHeader& header) const {
    auto parent_hash = header.parent_hash;
    if (parent_hash == current_head().hash) return current_head();

    auto parent_num = find_block(parent_hash);
    if (!parent_num.has_value()) return std::nullopt;

    return BlockId{*parent_num, parent_hash};
}

BlockNum Fork::distance_from_root(const BlockId& block) const {
    return block.number - canonical_chain_.initial_head().number;
}

Hash Fork::insert_header(const BlockHeader& header) {
    // skip 'if (!db::has_header(...header.hash())' to avoid hash computing (also write_header does an upsert)
    return db::write_header_ex(tx_, header, true);  // todo: move?

    // header_cache_.put(header.hash(), header);
}

void Fork::insert_body(const Block& block) {
    Hash block_hash = block.header.hash();  // todo: hash() is computationally expensive
    BlockNum block_num = block.header.number;

    if (!db::has_body(tx_, block_num, block_hash)) {
        db::write_body(tx_, block, block_hash, block_num);
    }
}

void Fork::extend_with(const Block& block) {
    ensure_invariant(extends_head(block.header), "inserting block must extend the head");

    Hash header_hash = insert_header(block.header);
    insert_body(block);

    canonical_chain_.advance(block.header.number, header_hash);

    current_head_ = {block.header.number, header_hash};
}

VerificationResult Fork::verify_chain() {
    SILK_TRACE << "Fork: verifying chain from head " << current_head_.hash.to_hex();

    // db commit policy
    bool commit_at_each_stage = is_first_sync_;
    if (!commit_at_each_stage) tx_.disable_commit();

    // forward
    Stage::Result forward_result = pipeline_.forward(tx_, current_head_.number);

    // evaluate result
    VerificationResult verify_result;
    switch (forward_result) {
        case Stage::Result::kSuccess: {
            ensure_invariant(pipeline_.head_header_number() == canonical_chain_.current_head().number &&
                                 pipeline_.head_header_hash() == canonical_chain_.current_head().hash,
                             "forward succeeded with pipeline head not aligned with canonical head");
            verify_result = ValidChain{pipeline_.head_header_number()};
            break;
        }
        case Stage::Result::kWrongFork:
        case Stage::Result::kInvalidBlock:
        case Stage::Result::kWrongStateRoot: {
            ensure_invariant(pipeline_.unwind_point().has_value(),
                             "unwind point from pipeline requested when forward fails");
            InvalidChain invalid_chain;
            invalid_chain.unwind_point.number = *pipeline_.unwind_point();
            invalid_chain.unwind_point.hash = *canonical_chain_.get_hash(*pipeline_.unwind_point());
            if (pipeline_.bad_block()) {
                invalid_chain.bad_block = pipeline_.bad_block();
                invalid_chain.bad_headers = collect_bad_headers(tx_, invalid_chain);
            }
            verify_result = invalid_chain;
            break;
        }
        case Stage::Result::kStoppedByEnv:
            verify_result = ValidChain{pipeline_.head_header_number(), pipeline_.head_header_hash()};
            break;
        default:
            verify_result = ValidationError{pipeline_.head_header_number(), pipeline_.head_header_hash()};
    }
    last_verified_head_ = current_head_;
    last_head_status_ = verify_result;

    // finish
    tx_.enable_commit();
    if (commit_at_each_stage) tx_.commit_and_renew();
    return verify_result;
}

bool Fork::notify_fork_choice_update(Hash head_block_hash, [[maybe_unused]] std::optional<Hash> finalized_block_hash) {
    SILK_TRACE << "Fork: fork choice update " << head_block_hash.to_hex();

    if (last_verified_head_.hash != head_block_hash) {
        // usually update_fork_choice must follow verify_chain with the same header
        // except when verify_chain returned InvalidChain, in which case we expect
        // update_fork_choice to be called with a previous valid head block hash
        auto head_block_num= find_block(head_block_hash);

        ensure_invariant(head_block_num.has_value(),
                         "fork choice update with unknown block hash");
        ensure_invariant(*head_block_num < last_verified_head_.number,
                         "fork choice update upon non verified block");

        auto unwind_result = pipeline_.unwind(tx_, *head_block_num);
        success_or_throw(unwind_result);  // unwind must complete with success

        canonical_chain_.delete_down_to(*head_block_num); // remove last part of canonical

        ensure_invariant(canonical_chain_.current_head().hash == head_block_hash,
                         "fork choice update failed to update canonical chain");

        last_verified_head_ = { *head_block_num, head_block_hash };
        last_head_status_ = ValidChain{*head_block_num, head_block_hash};
    }

    if (!holds_alternative<ValidChain>(last_head_status_)) return false;

    tx_.commit_and_renew();

    last_fork_choice_ = canonical_chain_.current_head();

    is_first_sync_ = false;

    return true;
}

std::set<Hash> Fork::collect_bad_headers(db::RWTxn& tx, InvalidChain& invalid_chain) {
    if (!invalid_chain.bad_block) return {};

    std::set<Hash> bad_headers;
    for (BlockNum current_height = canonical_chain_.current_head().number;
         current_height > invalid_chain.unwind_point.number; current_height--) {
        auto current_hash = db::read_canonical_hash(tx, current_height);
        bad_headers.insert(*current_hash);
    }

    return bad_headers;
}



std::vector<Fork>::const_iterator find_fork_with_head(const std::vector<Fork>& forks, const Hash& requested_head_hash) {
    return std::find_if(forks.begin(), forks.end(), [&](const auto& fork) {
        return fork.current_head().hash == requested_head_hash;
    });
}

std::vector<Fork>::const_iterator best_fork_to_extend(const std::vector<Fork>& forks, const BlockHeader& header) {
    return find_fork_with_head(forks, header.parent_hash);
}

std::vector<Fork>::const_iterator best_fork_to_branch(const std::vector<Fork>& forks, const BlockHeader& header) {
    auto fork = forks.end();
    BlockNum height = 0;
    for (auto f = forks.begin(); f != forks.end(); ++f) {
        auto attachment_point = f->find_attachment_point(header);
        if (!attachment_point) continue;
        auto distance = f->distance_from_root(*attachment_point);
        if (fork == forks.end() || distance < height) {
            height = distance;
            fork = f;
        }
    }

    return fork;
}

}  // namespace silkworm::stagedsync
