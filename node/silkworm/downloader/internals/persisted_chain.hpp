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

#include "chain_elements.hpp"
#include "db_tx.hpp"
#include "types.hpp"

namespace silkworm {

/*
 * PersistedChain represents the chain on the db; it has these responsibilities:
 *    - persist headers on the db
 *    - update canonical chain
 *    - detect unwind point
 *    - do headers unwind
 *    - signal (to other stages) to do an unwind operation
 * It is the counterpart of Erigon's HeaderInserter. Ideally it has to encapsulate all the details of the db
 * organization, but in practice this is not possible completely. Header downloader uses an instance of this class for
 * each forward() operation. When it receives headers from WorkingChain, that are ready to persist, the downloader call
 * persist() on PersistedChain. Conversely, in the unwind() operation the downloader call the PersistedChain's
 * remove_headers() method.
 *
 * PersistedChain has also the responsibility to detect a change in the canonical chain that is already persisted. In
 * this case the method unwind_point() reports the point to which we must return.
 */

class PersistedChain {
  public:
    explicit PersistedChain(Db::ReadWriteAccess::Tx& tx);

    void persist(const Headers&);
    void persist(const BlockHeader&);
    void close();

    static std::set<Hash> remove_headers(BlockNum new_height, Hash bad_block,
                                         std::optional<BlockNum>& new_max_block_num, Db::ReadWriteAccess::Tx& tx);

    bool best_header_changed() const;
    bool unwind_detected() const;  // todo: do we need both unwind() & unwind_detected() ?
    bool unwind() const;

    BlockNum unwind_point() const;
    BlockNum initial_height() const;
    BlockNum highest_height() const;
    Hash highest_hash() const;
    BigInt total_difficulty() const;

  private:
    BlockNum find_forking_point(Db::ReadWriteAccess::Tx&, const BlockHeader& header, BlockNum height,
                                const BlockHeader& parent);
    void update_canonical_chain(BlockNum heigth, Hash hash);

    Db::ReadWriteAccess::Tx& tx_;
    Hash previous_hash_;
    Hash highest_hash_;
    BlockNum initial_in_db_{};
    BlockNum highest_in_db_{};
    BigInt local_td_;
    BlockNum unwind_point_{};
    bool unwind_{false};
    bool unwind_detected_{false};
    bool new_canonical_{false};
    lru_cache<BlockNum, Hash> canonical_cache_;
    bool closed_{false};
};

}  // namespace silkworm

#endif  // SILKWORM_PERSISTED_CHAIN_HPP
