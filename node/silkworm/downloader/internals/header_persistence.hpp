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

#pragma once

#include <silkworm/common/lru_cache.hpp>
#include <silkworm/db/access_layer.hpp>

#include "chain_elements.hpp"
#include "types.hpp"

namespace silkworm {

/** HeaderPersistence save headers on the db. It has these responsibilities:
 *    - persist headers on the db
 *    - update canonical chain
 *    - detect unwind point
 *    - do headers unwind
 *    - signal (to other stages) to do an unwind operation
 * It is the counterpart of Erigon's HeaderInserter. Ideally it has to encapsulate all the details of the db
 * organization, but in practice this is not possible completely. Header downloader uses an instance of this class for
 * each forward() operation. When it receives headers from HeaderChain, that are ready to persist, the downloader call
 * persist() on HeaderPersistence. Conversely, in the unwind() operation the downloader call the HeaderPersistence's
 * remove_headers() method.
 *
 * HeaderPersistence has also the responsibility to detect a change in the canonical chain that is already persisted.
 * In this case the method unwind_point() reports the point to which we must return.
 */

class HeaderPersistence {
  public:
    explicit HeaderPersistence(db::RWTxn& tx);

    void persist(const Headers&);
    void persist(const BlockHeader&);
    void finish();

    static auto remove_headers(BlockNum unwind_point, std::optional<Hash> bad_block, db::RWTxn& tx)
        -> std::tuple<std::set<Hash>, BlockNum>;

    bool best_header_changed() const;
    bool unwind_needed() const;
    bool canonical_repaired() const;

    BlockNum unwind_point() const;
    BlockNum initial_height() const;
    BlockNum highest_height() const;
    Hash highest_hash() const;
    BigInt total_difficulty() const;

  private:
    static constexpr size_t kCanonicalCacheSize = 1000;

    BlockNum find_forking_point(db::RWTxn&, const BlockHeader& header, BlockNum height, const Hash& parent_hash);
    void update_canonical_chain(BlockNum height, Hash hash);

    db::RWTxn& tx_;
    Hash previous_hash_;
    Hash highest_hash_;
    BlockNum initial_in_db_{};
    BlockNum highest_in_db_{};
    BigInt local_td_;
    BlockNum unwind_point_{};
    bool unwind_needed_{false};
    bool new_canonical_{false};
    bool repaired_{false};
    lru_cache<BlockNum, Hash> canonical_cache_;
    bool finished_{false};
};

}  // namespace silkworm
