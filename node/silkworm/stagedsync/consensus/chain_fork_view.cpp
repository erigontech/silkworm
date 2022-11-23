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

#include "chain_fork_view.hpp"

#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>

namespace silkworm::stagedsync::consensus {

ChainForkView::ChainForkView(ExecutionEngine& ee) : exec_engine_{ee}, canonical_cache_(kCanonicalCacheSize) {
    std::tie(initial_head_.number, initial_head_.hash, initial_head_td_) = exec_engine_.get_headers_head();

    current_head_td_ = initial_head_td_;
    current_head_ = initial_head_;
}

bool ChainForkView::head_changed() const { return current_head_td_ != initial_head_td_; }

bool ChainForkView::unwind_needed() const { return unwind_point_.has_value(); }

BlockNum ChainForkView::head_height() const { return current_head_.number; }

Hash ChainForkView::head_hash() const { return current_head_.hash; }

BigInt ChainForkView::head_total_difficulty() const { return current_head_td_; }

BlockIdPair ChainForkView::unwind_point() const { return *unwind_point_; }

void ChainForkView::add(const BlockHeader& header) {  // try to modularize this method
    // Admittance conditions
    auto height = header.number;
    Hash hash = header.hash();
    if (hash == previous_hash_) {
        return;  // skip duplicates
    }

    // Calculate total difficulty
    auto parent_td = exec_engine_.get_header_td(height - 1, header.parent_hash);
    if (!parent_td) {
        std::string error_message = "Consensus: parent's total difficulty not found on Execution,"
            " hash= " + to_hex(header.parent_hash) +
            " height= " + std::to_string(height - 1) +
            " for header= " + hash.to_hex();
        log::Error("Consensus") << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > current_head_td_) {
        // find the forking point - i.e. the latest header on the canonical chain which is an ancestor of this one
        auto forking_point = find_forking_point(header, height, header.parent_hash);

        // Save progress
        current_head_.number = height;
        current_head_.hash = hash;
        current_head_td_ = td;  // this makes sure we end up choosing the chain with the max total difficulty

        canonical_cache_.put(height, hash);

        if (forking_point.number < unwind_point_->number) {  // See if the forking point affects the unwind-point
            unwind_point_ = forking_point;    // (the block number to which other stages will need to unwind)
        }
    }

    previous_hash_ = hash;
}

BlockIdPair ChainForkView::find_forking_point(const BlockHeader& header, BlockNum height, const Hash& parent_hash) {
    BlockIdPair forking_point{};

    // Read canonical hash at height-1
    auto prev_canon_hash = canonical_cache_.get_as_copy(height - 1);  // look in the cache first
    if (!prev_canon_hash) {
        prev_canon_hash = db::read_canonical_hash(tx, height - 1);  // then look in the db
    }

    // Most common case: forking point is the height of the parent header
    if (prev_canon_hash == header.parent_hash) {
        forking_point.number = height - 1;
        forking_point.hash = header.parent_hash;
    }
    // Going further back
    else {
        auto parent = exec_engine_.get_header(height - 1, parent_hash);
        if (!parent) {
            std::string error_message = "Consensus: parent non found on Execution,"
                " hash= " + to_hex(parent_hash) +
                " height= " + std::to_string(height - 1) +
                " for header= " + to_hex(header.hash());
            log::Error("Consensus") << error_message;
            throw std::logic_error(error_message);
        }

        auto ancestor_hash = parent->parent_hash;
        auto ancestor_height = height - 2;

        // look in the cache first
        const Hash* cached_canon_hash;
        while ((cached_canon_hash = canonical_cache_.get(ancestor_height)) && *cached_canon_hash != ancestor_hash) {
            auto ancestor = exec_engine_.get_header(ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }  // if this loop finds a prev_canon_hash the next loop will be executed, is this right?

        // now look in the db
        std::optional<Hash> db_canon_hash;
        while ((db_canon_hash = db::read_canonical_hash(tx, ancestor_height)) && db_canon_hash != ancestor_hash) {
            auto ancestor = exec_engine_.get_header(tx, ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_height is our forking point
        forking_point.number = ancestor_height;
        forking_point.hash = ancestor_hash;
    }

    return forking_point;
}

// On Erigon is fixCanonicalChain
void ChainForkView::update_canonical_chain(BlockNum height, Hash hash) {  // hash can be empty
    if (height == 0) return;

    auto ancestor_hash = hash;
    auto ancestor_height = height;

    std::optional<Hash> persisted_canon_hash = db::read_canonical_hash(tx_, ancestor_height);
    while (!persisted_canon_hash ||
           std::memcmp(persisted_canon_hash.value().bytes, ancestor_hash.bytes, kHashLength) != 0) {
        // while (persisted_canon_hash != ancestor_hash) { // better but gcc12 release erroneously raises a maybe-uninitialized warn
        db::write_canonical_hash(tx_, ancestor_height, ancestor_hash);

        auto ancestor = db::read_header(tx_, ancestor_height, ancestor_hash);
        if (ancestor == std::nullopt) {
            std::string msg =
                "HeaderPersistence: fix canonical chain failed at"
                " ancestor=" +
                std::to_string(ancestor_height) + " hash=" + ancestor_hash.to_hex();
            log::Error("HeaderStage") << msg;
            throw std::logic_error(msg);
        }

        ancestor_hash = ancestor->parent_hash;
        --ancestor_height;

        persisted_canon_hash = db::read_canonical_hash(tx_, ancestor_height);
    }
}

}
