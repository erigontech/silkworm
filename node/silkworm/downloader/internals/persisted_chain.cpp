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

#include <silkworm/common/log.hpp>

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
    initial_height_ = headers_height;  // in Erigon is highest_in_db_
}

bool PersistedChain::best_header_changed() { return new_canonical_; }

bool PersistedChain::unwind_detected() { return unwind_detected_; }

bool PersistedChain::unwind() { return unwind_; }

BlockNum PersistedChain::initial_height() { return initial_height_; }

BlockNum PersistedChain::highest_height() { return highest_bn_; }

Hash PersistedChain::highest_hash() { return highest_hash_; }

BigInt PersistedChain::total_difficulty() { return local_td_; }

BlockNum PersistedChain::unwind_point() { return unwind_point_; }

/*
func (hi *HeaderInserter) FeedHeader(db ethdb.StatelessRwTx, header *types.Header, blockHeight uint64) error {
        hash := header.Hash()
        if hash == hi.prevHash {
                // Skip duplicates
                return nil
        }
        if blockHeight < hi.prevHeight {
                return fmt.Errorf("[%s] headers are unexpectedly unsorted, got %d after %d", hi.logPrefix, blockHeight,
hi.prevHeight)
        }
        if oldH := rawdb.ReadHeader(db, hash, blockHeight); oldH != nil {
                // Already inserted, skip
                return nil
        }
        // Load parent header
        parent := rawdb.ReadHeader(db, header.ParentHash, blockHeight-1)
        if parent == nil {
                log.Warn(fmt.Sprintf("Could not find parent with hash %x and height %d for header %x %d",
header.ParentHash, blockHeight-1, hash, blockHeight))
                // Skip headers without parents
                return nil
        }
        // Parent's total difficulty
        parentTd, err := rawdb.ReadTd(db, header.ParentHash, blockHeight-1)
        if err != nil || parentTd == nil {
                return fmt.Errorf("[%s] parent's total difficulty not found with hash %x and height %d for header %x %d:
%v", hi.logPrefix, header.ParentHash, blockHeight-1, hash, blockHeight, err)
        }
        // Calculate total difficulty of this header using parent's total difficulty
        td := new(big.Int).Add(parentTd, header.Difficulty)
        // Now we can decide wether this header will create a change in the canonical head
        if td.Cmp(hi.localTd) > 0 {
                hi.newCanonical = true
                // Find the forking point - i.e. the latest header on the canonical chain which is an ancestor of this one
                // Most common case - forking point is the height of the parent header
                var forkingPoint uint64
                var ch common.Hash
                var err error
                if fromCache, ok := hi.canonicalCache.Get(blockHeight - 1); ok {
                        ch = fromCache.(common.Hash)
                } else {
                        if ch, err = rawdb.ReadCanonicalHash(db, blockHeight-1); err != nil {
                                return fmt.Errorf("reading canonical hash for height %d: %w", blockHeight-1, err)
                        }
                }
                if ch == header.ParentHash {
                        forkingPoint = blockHeight - 1
                } else {
                        // Going further back
                        ancestorHash := parent.ParentHash
                        ancestorHeight := blockHeight - 2
                        // Look in the cache first
                        for fromCache, ok := hi.canonicalCache.Get(ancestorHeight); ok; fromCache, ok = hi.canonicalCache.Get(ancestorHeight) {
                                ch = fromCache.(common.Hash)
                                if ch == ancestorHash {
                                    break
                                }
                                ancestor := rawdb.ReadHeader(db, ancestorHash, ancestorHeight)
                                ancestorHash = ancestor.ParentHash
                                ancestorHeight--
                        }
                        // Now look in the DB
                        for ch, err = rawdb.ReadCanonicalHash(db, ancestorHeight); err == nil && ch != ancestorHash; ch, err = rawdb.ReadCanonicalHash(db, ancestorHeight) {
                                ancestor := rawdb.ReadHeader(db, ancestorHash, ancestorHeight)
                                ancestorHash = ancestor.ParentHash
                                ancestorHeight--
                        }
                        if err != nil {
                                return fmt.Errorf("[%s] reading canonical hash for %d: %w", hi.logPrefix, ancestorHeight, err)
                        }
                        // Loop above terminates when either err != nil (handled already) or ch == ancestorHash, therefore ancestorHeight is our forking point forkingPoint = ancestorHeight
                }
                if err = rawdb.WriteHeadHeaderHash(db, hash); err != nil {
                        return fmt.Errorf("[%s] marking head header hash as %x: %w", hi.logPrefix, hash, err)
                }
                if err = stages.SaveStageProgress(db, stages.Headers, blockHeight); err != nil {
                        return fmt.Errorf("[%s] saving Headers progress: %w", hi.logPrefix, err)
                }
                hi.highest = blockHeight
                hi.highestHash = hash
                hi.highestTimestamp = header.Time
                hi.canonicalCache.Add(blockHeight, hash)
                // See if the forking point affects the unwindPoint (the block number to which other stages will need to unwind before the new canonical chain is applied)
                if forkingPoint < hi.unwindPoint { hi.unwindPoint = forkingPoint
                        hi.unwind = true
                }
                // This makes sure we end up chosing the chain with the max total difficulty
                hi.localTd.Set(td)
        }
        data, err2 := rlp.EncodeToBytes(header)
        if err2 != nil {
                return fmt.Errorf("[%s] failed to RLP encode header: %w", hi.logPrefix, err2)
        }
        if err = rawdb.WriteTd(db, hash, blockHeight, td); err != nil {
                return fmt.Errorf("[%s] failed to WriteTd: %w", hi.logPrefix, err)
        }
        if err = db.Put(dbutils.HeadersBucket, dbutils.HeaderKey(blockHeight, hash), data); err != nil {
                return fmt.Errorf("[%s] failed to store header: %w", hi.logPrefix, err)
        }
        hi.prevHash = hash
        return nil
}

*/

void PersistedChain::persist(const Headers& headers) {
    std::for_each(headers.begin(), headers.end(), [this](const auto& header) { persist(*header); });
}

void PersistedChain::persist(const BlockHeader& header) {  // todo: try to modularize
    // Admittance conditions
    auto height = header.number;
    Hash hash = header.hash();
    if (hash == previous_hash_) {
        return;  // skip duplicates
    }

    // Important note: this test is wrong, cause error with certain sequence of headers that are corrects
    //    if (height < highest_bn_) {    // in Erigon is "height < previous_height_" but previous_height_ is never
    //    updated so the test fails always
    //        std::string error_message = "PersistedChain: headers are unexpectedly unsorted, got " +
    //        std::to_string(height) +
    //                                    " after " + std::to_string(highest_bn_);
    //        SILKWORM_LOG(LogLevel::Error) << error_message;
    //        throw std::logic_error(error_message);  // unexpected condition, bug?
    //    }
    if (tx_.read_header(height, hash).has_value()) {
        return;  // already inserted, skip
    }
    auto parent = tx_.read_header(height - 1, header.parent_hash);
    if (!parent) {
        std::string error_message = "Could not find parent with hash " + to_hex(header.parent_hash) + " and height " +
                                    std::to_string(height - 1) + " for header " + hash.to_hex() + "\n";
        SILKWORM_LOG(LogLevel::Error) << error_message;
        throw std::logic_error(error_message);
    }

    // Calculate total difficulty
    auto parent_td = tx_.read_total_difficulty(height - 1, header.parent_hash);
    if (!parent_td) {
        std::string error_message = "PersistedChain: parent's total difficulty not found with hash " +
                                    to_hex(header.parent_hash) + " and height " + std::to_string(height - 1) +
                                    " for header " + hash.to_hex();
        SILKWORM_LOG(LogLevel::Error) << error_message;
        throw std::logic_error(error_message);  // unexpected condition, bug?
    }
    auto td = *parent_td + header.difficulty;  // calculated total difficulty of this header

    // Now we can decide whether this header will create a change in the canonical head
    if (td > local_td_) {
        new_canonical_ = true;

        // find the forking point - i.e. the latest header on the canonical chain which is an ancestor of this one
        BlockNum forking_point = find_forking_point(tx_, header, height, *parent);

        // Save progress
        tx_.write_head_header_hash(hash);                           // can throw exception, todo: catch & rethrow?
        tx_.write_stage_progress(db::stages::kHeadersKey, height);  // can throw exception, todo: catch & rethrow?

        highest_bn_ = height;
        highest_hash_ = hash;
        highest_timestamp_ = header.timestamp;
        canonical_cache_.put(height, hash);
        local_td_ =
            td;  // this makes sure we end up choosing the chain with the max total difficulty - todo: what this mean?

        if (forking_point < unwind_point_) {  // See if the forking point affects the unwind-point (the block number to
            unwind_point_ = forking_point;    // which other stages will need to unwind before the new canonical chain
            unwind_ = true;                   // is applied)
        }
    }

    // Save progress
    tx_.write_total_difficulty(height, hash, td);

    // Save header
    tx_.write_header(header, true);  // true = with_header_numbers

    SILKWORM_LOG(LogLevel::Info) << "PersistedChain: saved header height=" << height << " hash=" << hash << "\n";

    previous_hash_ = hash;
}

BlockNum PersistedChain::find_forking_point(Db::ReadWriteAccess::Tx& tx, const BlockHeader& header, BlockNum height,
                                            const BlockHeader& parent) {
    BlockNum forking_point{};

    // Read canonical hash at height-1
    Hash prev_canon_hash;
    const Hash* cached_prev_hash = canonical_cache_.get(height - 1);  // look in the cache first
    if (cached_prev_hash) {
        prev_canon_hash = *cached_prev_hash;
    } else {
        auto persisted_prev_hash = tx.read_canonical_hash(height - 1);  // then look in the db
        if (!persisted_prev_hash) {
            std::string error_message =
                "PersistedChain: error reading canonical hash for height " + std::to_string(height - 1);
            SILKWORM_LOG(LogLevel::Error) << error_message;
            throw std::logic_error(error_message);  // unexpected condition, bug?
        }
        prev_canon_hash = *persisted_prev_hash;
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
        }  // todo: if this loop finds a cached_canon_hash the next loop will be executed, is this right?

        // now look in the db
        std::optional<Hash> persisted_canon_hash;
        while ((persisted_canon_hash = tx.read_canonical_hash(ancestor_height)) &&
               persisted_canon_hash != ancestor_hash) {
            auto ancestor = tx.read_header(ancestor_height, ancestor_hash);
            ancestor_hash = ancestor->parent_hash;
            ancestor_height--;
        }
        if (persisted_canon_hash == std::nullopt) {
            std::string error_message =
                "PersistedChain: error reading canonical hash for height " + std::to_string(ancestor_height);
            SILKWORM_LOG(LogLevel::Error) << error_message;
            throw std::logic_error(error_message);  // unexpected condition, bug?
        }
        // loop above terminates when probable_canonical_hash == ancestor_hash, therefore ancestor_height is our forking
        // point
        forking_point = ancestor_height;
    }

    return forking_point;
}

/*
func fixCanonicalChain(logPrefix string, logEvery *time.Ticker, height uint64, hash common.Hash, tx ethdb.StatelessRwTx) error {
        if height == 0 {
            return nil
        }
        ancestorHash := hash
        ancestorHeight := height

        var ch common.Hash
        var err error
        for ch, err = rawdb.ReadCanonicalHash(tx, ancestorHeight); err == nil && ch != ancestorHash; ch, err = rawdb.ReadCanonicalHash(tx, ancestorHeight) {
                if err = rawdb.WriteCanonicalHash(tx, ancestorHash, ancestorHeight); err != nil {
                    return fmt.Errorf("[%s] marking canonical header %d %x: %w", logPrefix, ancestorHeight, ancestorHash, err)
                }
                ancestor := rawdb.ReadHeader(tx, ancestorHash, ancestorHeight)
                if ancestor == nil {
                        return fmt.Errorf("ancestor is nil. height %d, hash %x", ancestorHeight, ancestorHash)
                }

                select {
                case <-logEvery.C:
                        log.Info("fix canonical", "ancestor", ancestorHeight, "hash", ancestorHash)
                default:
                }
                ancestorHash = ancestor.ParentHash
                ancestorHeight--
        }
        if err != nil {
                return fmt.Errorf("[%s] reading canonical hash for %d: %w", logPrefix, ancestorHeight, err)
        }
        return nil
}

 */

void PersistedChain::update_canonical_chain(BlockNum height, Hash hash) {  // hash can be empty
    if (height == 0) return;

    auto ancestor_hash = hash;
    auto ancestor_height = height;

    std::optional<Hash> persisted_canon_hash = tx_.read_canonical_hash(ancestor_height);
    while (persisted_canon_hash != ancestor_hash) {
        tx_.write_canonical_hash(ancestor_height, ancestor_hash);

        auto ancestor = tx_.read_header(ancestor_height, ancestor_hash);
        if (ancestor == std::nullopt) {
            std::string msg = "PersistedChain: fix canonical chain failed at ancestor=" +
                              std::to_string(ancestor_height) + " hash=" + ancestor_hash.to_hex();
            SILKWORM_LOG(LogLevel::Error) << msg;
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

std::set<Hash> PersistedChain::remove_headers([[maybe_unused]] BlockNum unwind_point,
                                              [[maybe_unused]] Hash bad_block,
                                              [[maybe_unused]] Db::ReadWriteAccess::Tx& tx) {
    std::set<Hash> bad_headers;
    /*
        BlockNum headers_height = tx.read_stage_progress(db::stages::kHeadersKey);

        bool is_bad_block = (bad_block != Hash{});
        for(BlockNum current_height = headers_height; current_height > unwind_point; current_height--) {
            if (is_bad_block) {
                auto current_hash = tx.read_canonical_hash(current_height);
                bad_headers.insert(current_hash);
            }
            tx.delete_canonical_hash(current_height);
        }

        if (is_bad_block) {
            bad_headers.insert(bad_block);

            // todo: implement here
        }
    */
    return bad_headers;
}

}  // namespace silkworm