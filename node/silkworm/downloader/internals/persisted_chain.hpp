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

#ifndef SILKWORM_PERSISTED_CHAIN_HPP
#define SILKWORM_PERSISTED_CHAIN_HPP

#include <silkworm/common/lru_cache.hpp>

#include "db_tx.hpp"
#include "types.hpp"
#include "chain_elements.hpp"

namespace silkworm {

/*
type HeaderInserter struct {
        localTd          *big.Int
        logPrefix        string
        prevHash         common.Hash // Hash of previously seen header - to filter out potential duplicates
        highestHash      common.Hash
        newCanonical     bool
        unwind           bool
        prevHeight       uint64
        unwindPoint      uint64
        highest          uint64
        highestTimestamp uint64
        canonicalCache   *lru.Cache
}
 */

class PersistedChain {      // counterpart of Erigon HeaderInserter
  public:
    explicit PersistedChain(Db::ReadWriteAccess::Tx& tx);

    void persist(const Headers&);
    void persist(const BlockHeader&);
    void close();

    static auto remove_headers(BlockNum new_height, Hash bad_block, Db::ReadWriteAccess::Tx& tx) -> std::set<Hash>;

    bool best_header_changed();
    bool unwind_detected();     // todo: do we need both unwind() & unwind_detected() ?
    bool unwind();

    BlockNum unwind_point();
    BlockNum initial_height();
    BlockNum highest_height();
    Hash highest_hash();
    BigInt total_difficulty();
  private:
    BlockNum find_forking_point(Db::ReadWriteAccess::Tx&, const BlockHeader& header, BlockNum height, 
                                const BlockHeader& parent);
    void update_canonical_chain(BlockNum heigth, Hash hash);

    Db::ReadWriteAccess::Tx& tx_;
    Hash previous_hash_;
    Hash highest_hash_;
    BlockNum initial_height_{};
    BlockNum highest_bn_{};
    uint64_t highest_timestamp_{};
    //BlockNum previous_height_{};
    BigInt local_td_;
    BlockNum unwind_point_{};
    bool unwind_{false};
    bool unwind_detected_{false};
    bool new_canonical_{false};
    lru_cache<BlockNum,Hash> canonical_cache_;
    bool closed_{false};
};


} // namespace silkworm

#endif  // SILKWORM_PERSISTED_CHAIN_HPP
