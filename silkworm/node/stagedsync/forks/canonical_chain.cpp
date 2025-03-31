// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "canonical_chain.hpp"

#include <set>

#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/db_utils.hpp>
#include <silkworm/infra/common/ensure.hpp>

namespace silkworm::stagedsync {

CanonicalChain::CanonicalChain(
    db::RWTxn& tx,
    db::DataModelFactory data_model_factory,
    size_t cache_size)
    : tx_{tx},
      data_model_factory_{std::move(data_model_factory)},
      canonical_hash_cache_{std::make_unique<LruCache<BlockNum, Hash>>(cache_size)} {
    open();
}

CanonicalChain::CanonicalChain(const CanonicalChain& copy, db::RWTxn& new_tx)
    : tx_{new_tx},
      data_model_factory_{copy.data_model_factory_},
      initial_head_{copy.initial_head_},
      current_head_{copy.current_head_},
      canonical_hash_cache_{std::make_unique<LruCache<BlockNum, Hash>>(copy.canonical_hash_cache_->size())} {
    open();
}

CanonicalChain::CanonicalChain(CanonicalChain&& orig) noexcept
    : tx_{orig.tx_},
      data_model_factory_{std::move(orig.data_model_factory_)},
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
    std::tie(initial_head_.block_num, initial_head_.hash) = db::read_canonical_head(tx_);
    // Set current status
    current_head_ = initial_head_;
}

BlockId CanonicalChain::initial_head() const { return initial_head_; }
BlockId CanonicalChain::current_head() const { return current_head_; }

bool CanonicalChain::cache_enabled() const { return canonical_hash_cache_->max_size() > 0; }

BlockId CanonicalChain::find_forking_point(Hash header_hash) const {
    std::optional<BlockHeader> header = data_model().read_header(header_hash);
    if (!header) throw std::logic_error("find_forking_point precondition violation, header not found");

    return find_forking_point(*header, header_hash);
}

BlockId CanonicalChain::find_forking_point(const BlockHeader& header, Hash header_hash) const {
    BlockId forking_point{};

    if (header.number == 0) return forking_point;
    if (get_hash(header.number) == header_hash) return {header.number, header_hash};

    BlockNum block_num = header.number;
    Hash parent_hash = header.parent_hash;

    // Most common case: forking point is the block_num of the parent header
    auto prev_canon_hash = get_hash(block_num - 1);
    if (prev_canon_hash == header.parent_hash) {
        forking_point = {block_num - 1, *prev_canon_hash};
    }

    // Going further back
    else {
        auto parent = data_model().read_header(block_num - 1, parent_hash);
        ensure_invariant(parent.has_value(),
                         [&]() { return "canonical chain could not find parent with hash " + to_hex(parent_hash) +
                                        " and block_num " + std::to_string(block_num - 1); });

        auto ancestor_hash = parent->parent_hash;
        auto ancestor_block_num = block_num - 2;

        std::optional<Hash> canon_hash;
        while ((canon_hash = get_hash(ancestor_block_num)).has_value() && (canon_hash != ancestor_hash)) {
            auto ancestor = data_model().read_header(ancestor_block_num, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            --ancestor_block_num;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_block_num is our forking point
        forking_point = {ancestor_block_num, ancestor_hash};
    }

    return forking_point;
}

void CanonicalChain::advance(BlockNum block_num, Hash header_hash) {
    ensure_invariant(current_head_.block_num == block_num - 1,
                     [&]() { return std::string("canonical chain must advance gradually,") +
                                    " current head " + std::to_string(current_head_.block_num) +
                                    " expected head " + std::to_string(block_num - 1); });

    db::write_canonical_hash(tx_, block_num, header_hash);
    if (cache_enabled()) canonical_hash_cache_->put(block_num, header_hash);

    current_head_.block_num = block_num;
    current_head_.hash = header_hash;
}

void CanonicalChain::update_up_to(BlockNum block_num, Hash hash) {  // hash can be empty
    if (block_num == 0) return;

    auto ancestor_hash = hash;
    auto ancestor_block_num = block_num;

    std::optional<Hash> persisted_canon_hash = db::read_canonical_header_hash(tx_, ancestor_block_num);
    // while (persisted_canon_hash != ancestor_hash) { // better but gcc12 release erroneously raises a maybe-uninitialized warn
    while (!persisted_canon_hash ||
           std::memcmp(persisted_canon_hash.value().bytes, ancestor_hash.bytes, kHashLength) != 0) {
        db::write_canonical_hash(tx_, ancestor_block_num, ancestor_hash);
        if (cache_enabled()) canonical_hash_cache_->put(ancestor_block_num, ancestor_hash);

        auto ancestor = data_model().read_header(ancestor_block_num, ancestor_hash);
        ensure_invariant(ancestor.has_value(),
                         [&]() { return "fix canonical chain failed at ancestor= " + std::to_string(ancestor_block_num) +
                                        " hash=" + ancestor_hash.to_hex(); });

        ancestor_hash = ancestor->parent_hash;
        --ancestor_block_num;

        persisted_canon_hash = db::read_canonical_header_hash(tx_, ancestor_block_num);
    }

    current_head_.block_num = block_num;
    current_head_.hash = hash;
}

void CanonicalChain::delete_down_to(BlockNum unwind_point) {
    for (BlockNum current_block_num = current_head_.block_num; current_block_num > unwind_point; --current_block_num) {
        db::delete_canonical_hash(tx_, current_block_num);  // do not throw if not found
        if (cache_enabled()) canonical_hash_cache_->remove(current_block_num);
    }

    current_head_.block_num = unwind_point;
    auto current_head_hash = db::read_canonical_header_hash(tx_, unwind_point);
    ensure_invariant(current_head_hash.has_value(),
                     [&]() { return "hash not found on canonical at block_num " + std::to_string(unwind_point); });

    current_head_.hash = *current_head_hash;

    if (initial_head_.block_num > current_head_.block_num) {
        initial_head_ = current_head_;  // we went under the prev initial head
    }
}

std::optional<Hash> CanonicalChain::get_hash(BlockNum block_num) const {
    auto canon_hash = canonical_hash_cache_->get_as_copy(block_num);  // look in the cache first
    if (!canon_hash) {
        canon_hash = db::read_canonical_header_hash(tx_, block_num);         // then look in the db
        if (canon_hash) canonical_hash_cache_->put(block_num, *canon_hash);  // and cache it
    }
    return canon_hash;
}

bool CanonicalChain::has(Hash block_hash) const {
    auto header = data_model().read_header(block_hash);
    if (!header) return false;
    auto canonical_hash_at_same_block_num = get_hash(header->number);
    return canonical_hash_at_same_block_num == block_hash;
}

}  // namespace silkworm::stagedsync