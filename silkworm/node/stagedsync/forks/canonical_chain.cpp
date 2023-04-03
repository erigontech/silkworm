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

#include "canonical_chain.hpp"

#include <set>

#include <silkworm/core/common/as_range.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/db_utils.hpp>

namespace silkworm::stagedsync {

static void ensure_invariant(bool condition, const std::string& message) {
    if (!condition) {
        throw std::logic_error("CanonicalChain invariant violation: " + message);
    }
}

CanonicalChain::CanonicalChain(db::RWTxn& tx) : tx_{tx}, canonical_cache_{kCacheSize} {
    // Read head of canonical chain
    std::tie(initial_head_.number, initial_head_.hash) = db::read_canonical_head(tx_);
    // Set current status
    current_head_ = initial_head_;
}

BlockId CanonicalChain::initial_head() const { return initial_head_; }
BlockId CanonicalChain::current_head() const { return current_head_; }

BlockNum CanonicalChain::find_forking_point(db::RWTxn& tx, Hash header_hash) {
    BlockNum forking_point{};

    std::optional<BlockHeader> header = db::read_header(tx, header_hash);  // todo: maybe use parent cache?
    if (!header) throw std::logic_error("find_forking_point precondition violation, header not found");
    if (header->number == 0) return forking_point;

    BlockNum height = header->number;
    Hash parent_hash = header->parent_hash;

    // Read canonical hash at height-1
    auto prev_canon_hash = canonical_cache_.get_as_copy(height - 1);  // look in the cache first
    if (!prev_canon_hash) {
        prev_canon_hash = db::read_canonical_hash(tx, height - 1);  // then look in the db
    }

    // Most common case: forking point is the height of the parent header
    if (prev_canon_hash == header->parent_hash) {
        forking_point = height - 1;
    }
    // Going further back
    else {
        auto parent = db::read_header(tx, height - 1, parent_hash);  // todo: maybe use parent cache?
        ensure_invariant(parent.has_value(),
                         "canonical chain could not find parent with hash " + to_hex(parent_hash) +
                             " and height " + std::to_string(height - 1) + " for header " + to_hex(header->hash()));

        auto ancestor_hash = parent->parent_hash;
        auto ancestor_height = height - 2;

        // look in the cache first
        const Hash* cached_canon_hash;
        while ((cached_canon_hash = canonical_cache_.get(ancestor_height)) && *cached_canon_hash != ancestor_hash) {
            auto ancestor = db::read_header(tx, ancestor_height, ancestor_hash);  // todo: maybe use parent cache?
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }  // if this loop finds a prev_canon_hash the next loop will be executed, is this right?

        // now look in the db
        std::optional<Hash> db_canon_hash;
        while ((db_canon_hash = read_canonical_hash(tx, ancestor_height)) && db_canon_hash != ancestor_hash) {
            auto ancestor = db::read_header(tx, ancestor_height, ancestor_hash);  // todo: maybe use parent cache?
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_height is our forking point
        forking_point = ancestor_height;
    }

    return forking_point;
}

void CanonicalChain::update_up_to(BlockNum height, Hash hash) {  // hash can be empty
    if (height == 0) return;

    auto ancestor_hash = hash;
    auto ancestor_height = height;

    std::optional<Hash> persisted_canon_hash = db::read_canonical_hash(tx_, ancestor_height);
    // while (persisted_canon_hash != ancestor_hash) { // better but gcc12 release erroneously raises a maybe-uninitialized warn
    while (!persisted_canon_hash ||
           std::memcmp(persisted_canon_hash.value().bytes, ancestor_hash.bytes, kHashLength) != 0) {
        db::write_canonical_hash(tx_, ancestor_height, ancestor_hash);
        canonical_cache_.put(ancestor_height, ancestor_hash);

        auto ancestor = db::read_header(tx_, ancestor_height, ancestor_hash);  // todo: maybe use parent cache?
        ensure_invariant(ancestor.has_value(),
                         "fix canonical chain failed at ancestor= " + std::to_string(ancestor_height) +
                             " hash=" + ancestor_hash.to_hex());

        ancestor_hash = ancestor->parent_hash;
        --ancestor_height;

        persisted_canon_hash = db::read_canonical_hash(tx_, ancestor_height);
    }

    current_head_.number = height;
    current_head_.hash = hash;
}

void CanonicalChain::delete_down_to(BlockNum unwind_point) {
    for (BlockNum current_height = current_head_.number; current_height > unwind_point; current_height--) {
        db::delete_canonical_hash(tx_, current_height);  // do not throw if not found
        canonical_cache_.remove(current_height);
    }

    current_head_.number = unwind_point;
    auto current_head_hash = db::read_canonical_hash(tx_, unwind_point);
    ensure_invariant(current_head_hash.has_value(), "hash not found on canonical at height " + std::to_string(unwind_point));

    current_head_.hash = *current_head_hash;
}

auto CanonicalChain::get_hash(BlockNum height) -> std::optional<Hash> {
    return db::read_canonical_hash(tx_, height);
}

}  // namespace silkworm::stagedsync