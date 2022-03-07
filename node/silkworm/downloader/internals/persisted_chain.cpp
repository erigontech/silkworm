/*
    Copyright 2021 The Silkworm Authors

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

#include "persisted_chain.hpp"

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/log.hpp>

#include "silkworm/common/stopwatch.hpp"

namespace silkworm {

PersistedChain::PersistedChain(Db::ReadWriteAccess::Tx& tx) : tx_(tx), canonical_cache_(1000) {
    BlockNum headers_height = tx.read_stage_progress(db::stages::kHeadersKey);
    auto headers_head_hash = tx.read_canonical_hash(headers_height);
    if (!headers_head_hash) {
        update_canonical_chain(headers_height, *tx.read_head_header_hash());
        unwind_detected_ = true;
        return;
    }

    std::optional<BigInt> headers_head_td = tx.read_total_difficulty(headers_height, *headers_head_hash);
    if (!headers_head_td)
        throw std::logic_error("total difficulty of canonical hash at height " + std::to_string(headers_height) +
                               " not found in db");

    local_td_ = *headers_head_td;
    unwind_point_ = headers_height;
    initial_in_db_ = headers_height;  // in Erigon is highest_in_db_
    highest_in_db_ = headers_height;
}

bool PersistedChain::best_header_changed() const { return new_canonical_; }

bool PersistedChain::unwind_detected() const { return unwind_detected_; }

bool PersistedChain::unwind() const { return unwind_; }

BlockNum PersistedChain::initial_height() const { return initial_in_db_; }

BlockNum PersistedChain::highest_height() const { return highest_in_db_; }

Hash PersistedChain::highest_hash() const { return highest_hash_; }

BigInt PersistedChain::total_difficulty() const { return local_td_; }

BlockNum PersistedChain::unwind_point() const { return unwind_point_; }

// Erigon's func (hi *HeaderInserter) FeedHeader

void PersistedChain::persist(const Headers& headers) {
    SILK_TRACE << "PersistedChain: persisting " << headers.size() << " headers";
    if (headers.empty()) return;

    StopWatch measure_curr_scope;                  // only for test
    auto start_time = measure_curr_scope.start();  // only for test

    as_range::for_each(headers, [this](const auto& header) { persist(*header); });

    auto [end_time, _] = measure_curr_scope.lap();  // only for test

    log::Trace() << "[INFO] PersistedChain: saved " << headers.size() << " headers from height "
                 << header_at(headers.begin()).number << " to height " << header_at(headers.rbegin()).number
                 << " (duration=" << measure_curr_scope.format(end_time - start_time) << ")"; // only for test
}

void PersistedChain::persist(const BlockHeader& header) {  // todo: try to modularize
    // Admittance conditions
    auto height = header.number;
    Hash hash = header.hash();
    if (hash == previous_hash_) {
        return;  // skip duplicates
    }

    if (tx_.read_header(height, hash).has_value()) {
        return;  // already inserted, skip
    }
    auto parent = tx_.read_header(height - 1, header.parent_hash);
    if (!parent) {
        std::string error_message = "PersistedChain: could not find parent with hash " + to_hex(header.parent_hash) + " and height " +
                                    std::to_string(height - 1) + " for header " + hash.to_hex();
        log::Error() << error_message;
        throw std::logic_error(error_message);
    }

    // Calculate total difficulty
    auto parent_td = tx_.read_total_difficulty(height - 1, header.parent_hash);
    if (!parent_td) {
        std::string error_message = "PersistedChain: parent's total difficulty not found with hash " +
                                    to_hex(header.parent_hash) + " and height " + std::to_string(height - 1) +
                                    " for header " + hash.to_hex();
        log::Error() << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > local_td_) {
        new_canonical_ = true;

        // find the forking point - i.e. the latest header on the canonical chain which is an ancestor of this one
        BlockNum forking_point = find_forking_point(tx_, header, height, *parent);

        // Save progress
        tx_.write_head_header_hash(hash);                           // can throw exception
        tx_.write_stage_progress(db::stages::kHeadersKey, height);  // can throw exception

        highest_in_db_ = height;
        highest_hash_ = hash;
        // highest_timestamp_ = header.timestamp;
        canonical_cache_.put(height, hash);
        local_td_ = td;  // this makes sure we end up choosing the chain with the max total difficulty

        if (forking_point < unwind_point_) {  // See if the forking point affects the unwind-point (the block number to
            unwind_point_ = forking_point;    // which other stages will need to unwind before the new canonical chain
            unwind_ = true;                   // is applied
        }
    }

    // Save progress
    tx_.write_total_difficulty(height, hash, td);

    // Save header
    tx_.write_header(header, true);  // true = with_header_numbers

    // SILK_TRACE << "PersistedChain: saved header height=" << height << " hash=" << hash;

    previous_hash_ = hash;
}

BlockNum PersistedChain::find_forking_point(Db::ReadWriteAccess::Tx& tx, const BlockHeader& header, BlockNum height,
                                            const BlockHeader& parent) {
    BlockNum forking_point{};

    // Read canonical hash at height-1
    auto prev_canon_hash = canonical_cache_.get_as_copy(height - 1);  // look in the cache first
    if (!prev_canon_hash) {
        prev_canon_hash = tx.read_canonical_hash(height - 1);  // then look in the db
    }

    // Most common case: forking point is the height of the parent header
    if (prev_canon_hash == header.parent_hash) {
        forking_point = height - 1;
    }
    // Going further back
    else {
        auto ancestor_hash = parent.parent_hash;
        auto ancestor_height = height - 2;

        // look in the cache first
        const Hash* cached_canon_hash;
        while ((cached_canon_hash = canonical_cache_.get(ancestor_height)) && *cached_canon_hash != ancestor_hash) {
            auto ancestor = tx.read_header(ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            ancestor_height--;
        }  // if this loop finds a prev_canon_hash the next loop will be executed, is this right?

        // now look in the db
        std::optional<Hash> db_canon_hash;
        while ((db_canon_hash = tx.read_canonical_hash(ancestor_height)) && db_canon_hash != ancestor_hash) {
            auto ancestor = tx.read_header(ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            ancestor_height--;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_height is our forking point
        forking_point = ancestor_height;
    }

    return forking_point;
}

// On Erigon is fixCanonicalChain
void PersistedChain::update_canonical_chain(BlockNum height, Hash hash) {  // hash can be empty
    if (height == 0) return;

    auto ancestor_hash = hash;
    auto ancestor_height = height;

    std::optional<Hash> persisted_canon_hash = tx_.read_canonical_hash(ancestor_height);
    while (persisted_canon_hash != ancestor_hash) {
        tx_.write_canonical_hash(ancestor_height, ancestor_hash);

        auto ancestor = tx_.read_header(ancestor_height, ancestor_hash);
        if (ancestor == std::nullopt) {
            std::string msg = "PersistedChain: fix canonical chain failed at"
                " ancestor=" + std::to_string(ancestor_height) + " hash=" + ancestor_hash.to_hex();
            log::Error() << msg;
            throw std::logic_error(msg);
        }

        ancestor_hash = ancestor->parent_hash;
        ancestor_height--;

        persisted_canon_hash = tx_.read_canonical_hash(ancestor_height);
    }
}

void PersistedChain::close() {
    if (closed_) return;

    if (unwind()) return;

    if (highest_height() != 0) {
        update_canonical_chain(highest_height(), highest_hash());
    }

    closed_ = true;
}

std::set<Hash> PersistedChain::remove_headers(BlockNum unwind_point, Hash bad_block,
                                              std::optional<BlockNum>& max_block_num_ok, Db::ReadWriteAccess::Tx& tx) {
    std::set<Hash> bad_headers;
    max_block_num_ok.reset();

    BlockNum headers_height = tx.read_stage_progress(db::stages::kHeadersKey);

    // todo: the following code changed in Erigon, fix it

    bool is_bad_block = (bad_block != Hash{});
    for (BlockNum current_height = headers_height; current_height > unwind_point; current_height--) {
        if (is_bad_block) {
            auto current_hash = tx.read_canonical_hash(current_height);
            bad_headers.insert(*current_hash);
        }
        tx.delete_canonical_hash(current_height);  // do not throw if not found
    }

    if (is_bad_block) {
        bad_headers.insert(bad_block);

        auto [max_block_num, max_hash] = tx.header_with_biggest_td(&bad_headers);

        if (max_block_num == 0) {
            max_block_num = unwind_point;
            max_hash = *tx.read_canonical_hash(max_block_num);
        }

        tx.write_head_header_hash(max_hash);
    }

    return bad_headers;
}

}  // namespace silkworm
