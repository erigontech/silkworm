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

#pragma once

#include <atomic>
#include <concepts>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/node/db/access_layer.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>
#include <silkworm/node/stagedsync/stages/stage.hpp>

namespace silkworm::stagedsync {

class CanonicalChain {
  public:
    static constexpr size_t kNoCache = 0;

    explicit CanonicalChain(db::RWTxn&, size_t cache_size = kDefaultCacheSize);
    CanonicalChain(CanonicalChain&) = delete;           // tx is not copiable
    CanonicalChain(const CanonicalChain&, db::RWTxn&);  // we can copy a CanonicalChain giving a new tx
    CanonicalChain(CanonicalChain&&) noexcept;

    void open();

    BlockId find_forking_point(Hash header_hash) const;
    BlockId find_forking_point(const BlockHeader& header, Hash header_hash) const;

    void advance(BlockNum height, Hash header_hash);
    void update_up_to(BlockNum height, Hash header_hash);
    void delete_down_to(BlockNum unwind_point);
    void set_current_head(BlockId);

    BlockId initial_head() const;
    BlockId current_head() const;

    std::optional<Hash> get_hash(BlockNum height) const;
    bool has(Hash block_hash) const;

  private:
    db::RWTxn& tx_;
    db::DataModel data_model_;

    BlockId initial_head_{};
    BlockId current_head_{};

    static constexpr size_t kDefaultCacheSize = 1000;
    std::unique_ptr<lru_cache<BlockNum, Hash>> canonical_hash_cache_;  // uses unique_ptr because lru_cache is not movable
    bool cache_enabled() const;
};

}  // namespace silkworm::stagedsync
