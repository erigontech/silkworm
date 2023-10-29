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
#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/db_utils.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

#include "main_chain.hpp"

namespace silkworm::stagedsync {

Fork::Fork(BlockId forking_point, db::ROTxnManaged&& main_chain_tx, NodeSettings& ns)
    : main_tx_{std::move(main_chain_tx)},
      memory_db_{TemporaryDirectory::get_unique_temporary_path(ns.data_directory->forks().path()), &main_tx_},
      memory_tx_{memory_db_},
      data_model_{memory_tx_},
      pipeline_{&ns},
      canonical_chain_(memory_tx_) {
    // actual head
    current_head_ = forking_point;
    // go down if needed
    if (canonical_chain_.initial_head() != forking_point) {
        reduce_down_to(forking_point);
        ensure_invariant(canonical_chain_.current_head() == forking_point,
                         "forking point must be the current canonical head");
    }
}

void Fork::close() {
    if (memory_tx_.is_open())
        memory_tx_.abort();
}

void Fork::flush(db::RWTxn& main_chain_tx_) {
    memory_tx_.flush(main_chain_tx_);
}

BlockId Fork::current_head() const {
    return current_head_;
}

BlockId Fork::finalized_head() const {
    return finalized_head_;
}

std::optional<VerificationResult> Fork::head_status() const {
    return head_status_;
}

bool Fork::extends_head(const BlockHeader& header) const {
    return current_head().hash == header.parent_hash;
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
    return db::write_header_ex(memory_tx_, header, /*with_header_numbers=*/false);  // kHeaderNumbers table will be updated by stage blockhashes
}

void Fork::insert_body(const Block& block, const Hash& block_hash) {
    // avoid calculation of block.header.hash() because is computationally expensive
    BlockNum block_num = block.header.number;

    if (!data_model_.has_body(block_num, block_hash)) {
        db::write_body(memory_tx_, block, block_hash, block_num);
    }
}

void Fork::extend_with(const std::list<std::shared_ptr<Block>>& blocks) {
    for (auto const& block : blocks) {
        extend_with(*block);
    }
}

void Fork::extend_with(const Block& block) {
    ensure_invariant(extends_head(block.header), "inserting block must extend the head");

    Hash header_hash = insert_header(block.header);
    insert_body(block, header_hash);

    canonical_chain_.advance(block.header.number, header_hash);

    current_head_ = {block.header.number, header_hash};
}

void Fork::reduce_down_to(BlockId unwind_point) {
    ensure(unwind_point.number < canonical_chain_.current_head().number,
           "reducing down to a block above the fork head");

    // we do not handle differently the case where unwind_point.number > last_verified_head_.number
    // assuming pipeline unwind can handle it correctly

    auto unwind_result = pipeline_.unwind(memory_tx_, unwind_point.number);
    success_or_throw(unwind_result);  // unwind must complete with success

    ensure_invariant(pipeline_.head_header_number() == unwind_point.number &&
                         pipeline_.head_header_hash() == unwind_point.hash,
                     "unwind succeeded with pipeline head not aligned with unwind point");

    canonical_chain_.delete_down_to(unwind_point.number);  // remove last part of canonical

    ensure_invariant(canonical_chain_.current_head().hash == unwind_point.hash,
                     "canonical chain not updated to unwind point");

    head_status_ = ValidChain{unwind_point};

    current_head_ = unwind_point;
}

VerificationResult Fork::verify_chain() {
    SILK_TRACE << "Fork: verifying chain from head " << current_head_.hash.to_hex();

    // db commit policy
    memory_tx_.disable_commit();

    // forward
    Stage::Result forward_result = pipeline_.forward(memory_tx_, current_head_.number);

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
                invalid_chain.bad_headers = collect_bad_headers(invalid_chain);
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

    head_status_ = verify_result;

    // finish, no commit here
    return verify_result;
}

bool Fork::fork_choice(Hash head_block_hash, std::optional<Hash> finalized_block_hash) {
    SILK_TRACE << "Fork: fork choice update " << head_block_hash.to_hex();

    /* this block is to handle fork choice in the middle of this fork; it requires suitable ExecutionEngine behavior
       to be enabled, which is not the case at the moment
    if (last_verified_head_.hash != head_block_hash) {
        // usually update_fork_choice must follow verify_chain with the same header
        // except when verify_chain returned InvalidChain, in which case we expect
        // update_fork_choice to be called with a previous valid head block hash
        auto head_block_num = find_block(head_block_hash);

        ensure_invariant(head_block_num.has_value(),
                         "fork choice update with unknown block hash");
        ensure_invariant(*head_block_num < last_verified_head_.number,
                         "fork choice update upon non verified block");

        auto unwind_result = pipeline_.unwind(memory_tx_, *head_block_num);
        success_or_throw(unwind_result);  // unwind must complete with success

        canonical_chain_.delete_down_to(*head_block_num);  // remove last part of canonical

        ensure_invariant(canonical_chain_.current_head().hash == head_block_hash,
                         "fork choice update failed to update canonical chain");

        current_head_ = {*head_block_num, head_block_hash};
        head_status_ = ValidChain{*head_block_num, head_block_hash};
    }
    */

    ensure_invariant(current_head_.hash == head_block_hash, "fork choice update with wrong head block hash");

    if (!head_status_ || !holds_alternative<ValidChain>(*head_status_)) return false;

    // todo: check if is_canonical(*finalized_block_hash)

    db::write_last_head_block(memory_tx_, head_block_hash);

    if (finalized_block_hash) {
        db::write_last_finalized_block(memory_tx_, *finalized_block_hash);
        auto finalized_header = get_header(*finalized_block_hash);
        finalized_head_ = {finalized_header->number, *finalized_block_hash};
    }

    memory_tx_.enable_commit();
    memory_tx_.commit_and_stop();

    return true;
}

std::set<Hash> Fork::collect_bad_headers(InvalidChain& invalid_chain) {
    if (!invalid_chain.bad_block) return {};

    std::set<Hash> bad_headers;
    for (BlockNum current_height = canonical_chain_.current_head().number;
         current_height > invalid_chain.unwind_point.number; current_height--) {
        auto current_hash = canonical_chain_.get_hash(current_height);
        bad_headers.insert(*current_hash);
    }

    return bad_headers;
}

std::optional<BlockHeader> Fork::get_header(Hash header_hash) const {
    std::optional<BlockHeader> header = data_model_.read_header(header_hash);
    return header;
}

std::vector<Fork>::iterator find_fork_by_head(std::vector<Fork>& forks, const Hash& requested_head_hash) {
    return std::find_if(forks.begin(), forks.end(), [&](const auto& fork) {
        return fork.current_head().hash == requested_head_hash;
    });
}

std::vector<Fork>::iterator find_fork_to_extend(std::vector<Fork>& forks, const BlockHeader& header) {
    return find_fork_by_head(forks, header.parent_hash);
}

/*
std::vector<Fork>::iterator best_fork_to_branch(std::vector<Fork>& forks, const BlockHeader& header) {
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
*/

}  // namespace silkworm::stagedsync
