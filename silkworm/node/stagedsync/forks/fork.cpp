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
      canonical_chain_(tx_)
// header_cache_{kCacheSize}
{
    ensure_invariant(canonical_chain_.initial_head() == forking_point, "forking point must be the current canonical head");
    current_head_ = forking_point;
}

auto Fork::current_head() -> BlockId {
    return current_head_;
}

auto Fork::last_verified_head() -> BlockId {
    return canonical_chain_.current_head();
}

auto Fork::last_head_status() -> VerificationResult {
    return canonical_head_status_;
}

auto Fork::extends_current_head(const BlockHeader& header) -> bool {
    return current_head().hash == header.parent_hash;
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

void Fork::insert_block_over_head(const Block& block) {
    ensure_invariant(extends_current_head(block.header), "inserting block must extend the head");

    Hash header_hash = insert_header(block.header);
    insert_body(block);

    current_head_ = {block.header.number, header_hash};
}

auto Fork::verify_chain(Hash head_block_hash) -> VerificationResult {
    SILK_TRACE << "ExecutionEngine: verifying chain " << head_block_hash.to_hex();

    // retrieve the head header
    auto header = get_header(head_block_hash);
    ensure_invariant(header.has_value(), "header to verify non present");

    // db commit policy
    bool commit_at_each_stage = is_first_sync_;
    if (!commit_at_each_stage) tx_.disable_commit();

    // the new head is on a new fork?
    BlockNum forking_point = canonical_chain_.find_forking_point(tx_, head_block_hash);  // the forking origin

    if (forking_point < canonical_chain_.current_head().number) {  // if the forking is behind the current head
        // we need to do unwind to change canonical
        auto unwind_result = pipeline_.unwind(tx_, forking_point);
        success_or_throw(unwind_result);  // unwind must complete with success
        // remove last part of canonical
        canonical_chain_.delete_down_to(forking_point);
    }

    // update canonical up to header_hash
    canonical_chain_.update_up_to(header->number, head_block_hash);

    // forward
    Stage::Result forward_result = pipeline_.forward(tx_, header->number);

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
            InvalidChain invalid_chain = {*pipeline_.unwind_point()};
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
    canonical_head_status_ = verify_result;

    // finish
    tx_.enable_commit();
    if (commit_at_each_stage) tx_.commit_and_renew();
    return verify_result;
}

bool Fork::notify_fork_choice_update(Hash head_block_hash, [[maybe_unused]] std::optional<Hash> finalized_block_hash) {
    if (canonical_chain_.current_head().hash != head_block_hash) {
        // usually update_fork_choice must follow verify_chain with the same header
        // except when verify_chain returned InvalidChain, in which case we expect
        // update_fork_choice to be called with a previous valid head block hash

        auto verification = verify_chain(head_block_hash);

        if (!std::holds_alternative<ValidChain>(verification)) return false;

        ensure_invariant(canonical_chain_.current_head().hash == head_block_hash,
                         "canonical head not aligned with fork choice");
    }

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

    /*  todo: check if we need also the following code (remember that this entire algo changed in Erigon)
    BlockNum new_height = unwind_point;
    if (is_bad_block) {
        bad_headers.insert(*bad_block);

        auto [max_block_num, max_hash] = header_with_biggest_td(tx, &bad_headers);

        if (max_block_num == 0) {
            max_block_num = unwind_point;
            max_hash = *db::read_canonical_hash(tx, max_block_num);
        }

        db::write_head_header_hash(tx, max_hash);
        new_height = max_block_num;
    }
    return {bad_headers, new_height};
    */
    return bad_headers;
}

auto Fork::get_header(Hash header_hash) -> std::optional<BlockHeader> {
    // const BlockHeader* cached = header_cache_.get(header_hash);
    // if (cached) {
    //     return *cached;
    // }
    std::optional<BlockHeader> header = db::read_header(tx_, header_hash);
    return header;
}

auto Fork::get_header(BlockNum header_height, Hash header_hash) -> std::optional<BlockHeader> {
    // const BlockHeader* cached = header_cache_.get(header_hash);
    // if (cached) {
    //     return *cached;
    // }
    std::optional<BlockHeader> header = db::read_header(tx_, header_height, header_hash);
    return header;
}

auto Fork::get_canonical_hash(BlockNum height) -> std::optional<Hash> {
    auto hash = db::read_canonical_hash(tx_, height);
    return hash;
}

auto Fork::get_header_td(BlockNum header_height, Hash header_hash) -> std::optional<TotalDifficulty> {
    return db::read_total_difficulty(tx_, header_height, header_hash);
}

auto Fork::get_body(Hash header_hash) -> std::optional<BlockBody> {
    BlockBody body;
    bool found = read_body(tx_, header_hash, body);
    if (!found) return {};
    return body;
}

auto Fork::get_block_progress() -> BlockNum {
    BlockNum block_progress = 0;

    read_headers_in_reverse_order(tx_, 1, [&block_progress](BlockHeader&& header) {
        block_progress = header.number;
    });

    return block_progress;
}

auto Fork::get_last_headers(BlockNum limit) -> std::vector<BlockHeader> {
    std::vector<BlockHeader> headers;

    read_headers_in_reverse_order(tx_, limit, [&headers](BlockHeader&& header) {
        headers.emplace_back(std::move(header));
    });

    return headers;
}

auto Fork::is_ancestor(BlockId supposed_parent, BlockId block) -> bool {
    return extends(block, supposed_parent);
}

auto Fork::extends_last_fork_choice(BlockNum height, Hash hash) -> bool {
    return extends({height, hash}, last_fork_choice_);
}

auto Fork::extends(BlockId block, BlockId supposed_parent) -> bool {
    while (block.number > supposed_parent.number) {
        auto header = get_header(block.number, block.hash);
        if (!header) return false;
        if (header->parent_hash == supposed_parent.hash) return true;
        block.number--;
        block.hash = header->parent_hash;
    }
    if (block.number == supposed_parent.number) return block.hash == supposed_parent.hash;

    return false;
}

/*
auto Fork::get_canonical_head_from_db() -> ChainHead {
    auto [height, hash] = db::read_canonical_head(tx_);

    std::optional<TotalDifficulty> td = db::read_total_difficulty(tx_, height, hash);
    ensure_invariant(td.has_value(),
                     "total difficulty of canonical hash at height " + std::to_string(height) + " not found in db");

    return {height, hash, *td};
}
*/

}  // namespace silkworm::stagedsync
