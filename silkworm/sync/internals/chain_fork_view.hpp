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

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/node/stagedsync/execution_engine.hpp>
#include <silkworm/sync/internals/types.hpp>

namespace silkworm::chainsync {

// ChainForkView has the responsibility to maintains a view of forks in the recent history of headers
// Currently it only use a lru_cache<Hash, Total_Difficulty>, if it will need a full header cache it may use
// an lru_cache<Hash, std::shared_ptr<BlockHeader>>, accepting std::shared_ptr<BlockHeader> in the add() method
// to avoid coping header shared with HeaderStages.
// The lru_cache is not for performance: the ExecutionEngine currently computes and writes the header's total difficulty
// only when the verify_chain() method is called so the newly headers that the downloader received and inserted into
// the ExecutionEngine have not yet total difficulty computed.

class ChainForkView {
  public:
    ChainForkView(ChainHead headers_head);

    void reset_head(BlockId headers_head);

    TotalDifficulty add(const BlockHeader&);

    ChainHead head() const;
    BlockNum head_height() const;
    Hash head_hash() const;
    TotalDifficulty head_total_difficulty() const;

    bool head_changed() const;

    std::optional<TotalDifficulty> get_total_difficulty(const Hash& hash);
    std::optional<TotalDifficulty> get_total_difficulty(BlockNum height, const Hash& hash);

  private:
    ChainHead initial_head_{};
    ChainHead current_head_{};  // current head of the chain
    Hash previous_hash_;

    static constexpr size_t kCacheSize = 4096;
    lru_cache<Hash, TotalDifficulty> td_cache_;  // this is not for performance
};

}  // namespace silkworm::chainsync