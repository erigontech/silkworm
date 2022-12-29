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

#include "header_persistence.hpp"

#include <silkworm/common/as_range.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/db/stages.hpp>

#include "db_utils.hpp"
#include "silkworm/common/stopwatch.hpp"

namespace silkworm {

HeaderPersistence::HeaderPersistence(db::RWTxn& tx) : tx_(tx), canonical_cache_(kCanonicalCacheSize) {
    BlockNum headers_height = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);
    auto headers_hash = db::read_canonical_hash(tx, headers_height);
    if (!headers_hash) {
        headers_hash = db::read_head_header_hash(tx);  // here we assume: headers_height = height(head_header)
        update_canonical_chain(headers_height, *headers_hash);
        repaired_ = true;
    }

    std::optional<BigInt> headers_head_td = db::read_total_difficulty(tx, headers_height, *headers_hash);
    if (!headers_head_td)
        throw std::logic_error("total difficulty of canonical hash at height " + std::to_string(headers_height) +
                               " not found in db");

    local_td_ = *headers_head_td;
    unwind_point_ = headers_height;
    initial_in_db_ = headers_height;  // in Erigon is highest_in_db_
    highest_in_db_ = headers_height;  // TODO (mike) set highest_hash_?
}

bool HeaderPersistence::best_header_changed() const { return new_canonical_; }

bool HeaderPersistence::unwind_needed() const { return unwind_needed_; }

bool HeaderPersistence::canonical_repaired() const { return repaired_; }

BlockNum HeaderPersistence::initial_height() const { return initial_in_db_; }

BlockNum HeaderPersistence::highest_height() const { return highest_in_db_; }

Hash HeaderPersistence::highest_hash() const { return highest_hash_; }

BigInt HeaderPersistence::total_difficulty() const { return local_td_; }

BlockNum HeaderPersistence::unwind_point() const { return unwind_point_; }

// Erigon's func (hi *HeaderInserter) FeedHeader

void HeaderPersistence::persist(const Headers& headers) {
    SILK_TRACE << "HeaderPersistence: persisting " << headers.size() << " headers";
    if (headers.empty()) return;

    StopWatch measure_curr_scope;                  // only for test
    auto start_time = measure_curr_scope.start();  // only for test

    as_range::for_each(headers, [this](const auto& header) { persist(*header); });

    auto [end_time, _] = measure_curr_scope.lap();  // only for test

    log::Trace() << "[INFO] HeaderPersistence: saved " << headers.size() << " headers from height "
                 << header_at(headers.begin()).number << " to height " << header_at(headers.rbegin()).number
                 << " (duration=" << measure_curr_scope.format(end_time - start_time) << ")";  // only for test
}

void HeaderPersistence::persist(const BlockHeader& header) {  // try to modularize this method
    if (finished_) {
        std::string error_message = "HeaderPersistence: persist method called on instance in 'finished' state";
        log::Error("HeaderStage") << error_message;
        throw std::logic_error(error_message);
    }

    // Admittance conditions
    auto height = header.number;
    Hash hash = header.hash();
    if (hash == previous_hash_) {
        return;  // skip duplicates
    }

    if (db::read_header(tx_, height, hash).has_value()) {
        return;  // already inserted, skip
    }

    // Calculate total difficulty
    auto parent_td = db::read_total_difficulty(tx_, height - 1, header.parent_hash);
    if (!parent_td) {
        std::string error_message = "HeaderPersistence: parent's total difficulty not found with hash " +
                                    to_hex(header.parent_hash) + " and height " + std::to_string(height - 1) +
                                    " for header " + hash.to_hex();
        log::Error("HeaderStage") << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > local_td_) {
        new_canonical_ = true;

        // find the forking point - i.e. the latest header on the canonical chain which is an ancestor of this one
        BlockNum forking_point = find_forking_point(tx_, header, height, header.parent_hash);

        // Save progress
        db::write_head_header_hash(tx_, hash);                                   // can throw exception
        db::stages::write_stage_progress(tx_, db::stages::kHeadersKey, height);  // can throw exception

        highest_in_db_ = height;
        highest_hash_ = hash;
        // highest_timestamp_ = header.timestamp;
        canonical_cache_.put(height, hash);
        local_td_ = td;  // this makes sure we end up choosing the chain with the max total difficulty

        if (forking_point < unwind_point_) {  // See if the forking point affects the unwind-point (the block number to
            unwind_point_ = forking_point;    // which other stages will need to unwind before the new canonical chain
            unwind_needed_ = true;            // is applied
        }
    }

    // Save progress
    db::write_total_difficulty(tx_, height, hash, td);

    // Save header
    db::write_header(tx_, header, true);  // true = with_header_numbers

    // SILK_TRACE << "HeaderPersistence: saved header height=" << height << " hash=" << hash;

    previous_hash_ = hash;
}

BlockNum HeaderPersistence::find_forking_point(db::RWTxn& tx, const BlockHeader& header, BlockNum height,
                                               const Hash& parent_hash) {
    BlockNum forking_point{};

    // Read canonical hash at height-1
    auto prev_canon_hash = canonical_cache_.get_as_copy(height - 1);  // look in the cache first
    if (!prev_canon_hash) {
        prev_canon_hash = db::read_canonical_hash(tx, height - 1);  // then look in the db
    }

    // Most common case: forking point is the height of the parent header
    if (prev_canon_hash == header.parent_hash) {
        forking_point = height - 1;
    }
    // Going further back
    else {
        auto parent = db::read_header(tx_, height - 1, parent_hash);
        if (!parent) {
            std::string error_message = "HeaderPersistence: could not find parent with hash " + to_hex(parent_hash) +
                                        " and height " + std::to_string(height - 1) + " for header " + to_hex(header.hash());
            log::Error("HeaderStage") << error_message;
            throw std::logic_error(error_message);
        }

        auto ancestor_hash = parent->parent_hash;
        auto ancestor_height = height - 2;

        // look in the cache first
        const Hash* cached_canon_hash;
        while ((cached_canon_hash = canonical_cache_.get(ancestor_height)) && *cached_canon_hash != ancestor_hash) {
            auto ancestor = db::read_header(tx, ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }  // if this loop finds a prev_canon_hash the next loop will be executed, is this right?

        // now look in the db
        std::optional<Hash> db_canon_hash;
        while ((db_canon_hash = read_canonical_hash(tx, ancestor_height)) && db_canon_hash != ancestor_hash) {
            auto ancestor = db::read_header(tx, ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            --ancestor_height;
        }

        // loop above terminates when prev_canon_hash == ancestor_hash, therefore ancestor_height is our forking point
        forking_point = ancestor_height;
    }

    return forking_point;
}

// On Erigon is fixCanonicalChain
void HeaderPersistence::update_canonical_chain(BlockNum height, Hash hash) {  // hash can be empty
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

void HeaderPersistence::finish() {
    if (finished_) return;

    if (unwind_needed()) return;

    if (highest_height() != initial_height()) {
        update_canonical_chain(highest_height(), highest_hash());
    }

    finished_ = true;
}

std::tuple<std::set<Hash>, BlockNum>
HeaderPersistence::remove_headers(BlockNum unwind_point, std::optional<Hash> bad_block, db::RWTxn& tx) {
    BlockNum headers_height = db::stages::read_stage_progress(tx, db::stages::kHeadersKey);

    // todo: the following code changed in Erigon, fix it

    std::set<Hash> bad_headers;
    bool is_bad_block = bad_block.has_value();
    for (BlockNum current_height = headers_height; current_height > unwind_point; current_height--) {
        if (is_bad_block) {
            auto current_hash = db::read_canonical_hash(tx, current_height);
            bad_headers.insert(*current_hash);
        }
        db::delete_canonical_hash(tx, current_height);  // do not throw if not found
    }

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

    db::stages::write_stage_progress(tx, db::stages::kHeadersKey, new_height);

    return {bad_headers, new_height};
}

}  // namespace silkworm
