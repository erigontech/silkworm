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

#include <silkworm/infra/common/ensure.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/db/db_utils.hpp>

namespace silkworm::stagedsync {

CanonicalChain::CanonicalChain(db::RWTxn& tx, size_t cache_size)
    : tx_{tx},
      data_model_{tx_},  // todo: put an header cache into the data_model_ and share the data_model_ with the owner
      canonical_hash_cache_{std::make_unique<lru_cache<BlockNum, Hash>>(cache_size)} {
    open();
}

CanonicalChain::CanonicalChain(const CanonicalChain& copy, db::RWTxn& new_tx)
    : tx_{new_tx},
      data_model_{tx_},
      initial_head_{copy.initial_head_},
      current_head_{copy.current_head_},
      canonical_hash_cache_{std::make_unique<lru_cache<BlockNum, Hash>>(copy.canonical_hash_cache_->size())} {
    open();
}

CanonicalChain::CanonicalChain(CanonicalChain&& orig) noexcept
    : tx_{orig.tx_},
      data_model_{tx_},
      initial_head_{orig.initial_head_},
      current_head_{orig.current_head_},
      canonical_hash_cache_{std::move(orig.canonical_hash_cache_)} {
    open();
}

void CanonicalChain::set_current_head(BlockId head) {
    current_head_ = head;
    canonical_hash_cache_->clear();  // invalidate cache
}

void CanonicalChain::open() {
    // Read head of canonical chain
    std::tie(initial_head_.number, initial_head_.hash) = db::read_canonical_head(tx_);
    // Set current status
    current_head_ = initial_head_;
}

BlockId CanonicalChain::initial_head() const { return initial_head_; }
BlockId CanonicalChain::current_head() const { return current_head_; }

bool CanonicalChain::cache_enabled() const { return canonical_hash_cache_->max_size() > 0; }

BlockId CanonicalChain::find_forking_point(Hash header_hash) const {
    std::optional<BlockHeader> header = data_model_.read_header(header_hash);
    if (!header) throw std::logic_error("find_forking_point precondition violation, header not found");

    return find_forking_point(*header, header_hash);
}

BlockId CanonicalChain::find_forking_point(const BlockHeader& header, Hash header_hash) const {
    BlockId forking_point{};

    if (header.number == 0) return forking_point;
    if (get_hash(header.number) == header_hash) return {header.number, header_hash};

    BlockNum height = header.number;
    Hash parent_hash = header.parent_hash;

    // Most common case: forking point is the height of the parent header
    auto prev_canon_hash = get_hash(height - 1);
    if (prev_canon_hash == header.parent_hash) {
        forking_point = {height - 1, *prev_canon_hash};
    }

    // Going further back
    else {
        auto parent = data_model_.read_header(height - 1, parent_hash);
        ensure_invariant(parent.has_value(),
                         [&]() { return "canonical chain could not find parent with hash " + to_hex(parent_hash) +
                                        " and height " + std::to_string(height - 1); });

        auto ancestor_hash = parent->parent_hash;
        auto ancestor_height = height - 2;

        std::optional<Hash> canon_hash;
        while ((canon_hash = get_hash(ancestor_height)) && canon_hash != ancestor_hash) {
            auto ancestor = data_model_.read_header(ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_height is our forking point
        forking_point = {ancestor_height, ancestor_hash};
    }

    return forking_point;
}

void CanonicalChain::advance(BlockNum height, Hash header_hash) {
    ensure_invariant(current_head_.number == height - 1,
                     [&]() { return std::string("canonical chain must advance gradually,") +
                                    " current head " + std::to_string(current_head_.number) +
                                    " expected head " + std::to_string(height - 1); });

    db::write_canonical_hash(tx_, height, header_hash);
    if (cache_enabled()) canonical_hash_cache_->put(height, header_hash);

    current_head_.number = height;
    current_head_.hash = header_hash;
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
        if (cache_enabled()) canonical_hash_cache_->put(ancestor_height, ancestor_hash);

        auto ancestor = data_model_.read_header(ancestor_height, ancestor_hash);
        ensure_invariant(ancestor.has_value(),
                         [&]() { return "fix canonical chain failed at ancestor= " + std::to_string(ancestor_height) +
                                        " hash=" + ancestor_hash.to_hex(); });

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
        if (cache_enabled()) canonical_hash_cache_->remove(current_height);
    }

    current_head_.number = unwind_point;
    auto current_head_hash = db::read_canonical_hash(tx_, unwind_point);
    ensure_invariant(current_head_hash.has_value(),
                     [&]() { return "hash not found on canonical at height " + std::to_string(unwind_point); });

    current_head_.hash = *current_head_hash;

    if (initial_head_.number > current_head_.number) {
        initial_head_ = current_head_;  // we went under the prev initial head
    }
}

std::optional<Hash> CanonicalChain::get_hash(BlockNum height) const {
    auto canon_hash = canonical_hash_cache_->get_as_copy(height);  // look in the cache first
    if (!canon_hash) {
        canon_hash = db::read_canonical_hash(tx_, height);                // then look in the db
        if (canon_hash) canonical_hash_cache_->put(height, *canon_hash);  // and cache it
    }
    return canon_hash;
}

bool CanonicalChain::has(Hash block_hash) const {
    auto header = data_model_.read_header(block_hash);
    if (!header) return false;
    auto canonical_hash_at_same_height = get_hash(header->number);
    return canonical_hash_at_same_height == block_hash;
}

}  // namespace silkworm::stagedsync