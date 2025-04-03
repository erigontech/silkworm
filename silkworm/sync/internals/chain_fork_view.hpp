// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/chain_head.hpp>
#include <silkworm/sync/internals/types.hpp>

namespace silkworm::chainsync {

// ChainForkView has the responsibility to maintains a view of forks in the recent history of headers
// Currently it only use a LruCache<Hash, Total_Difficulty>, if it will need a full header cache it may use
// an LruCache<Hash, std::shared_ptr<BlockHeader>>, accepting std::shared_ptr<BlockHeader> in the add() method
// to avoid coping header shared with HeaderStages.
// The LruCache is not for performance: the ExecutionEngine currently computes and writes the header's total difficulty
// only when the verify_chain() method is called so the newly headers that the downloader received and inserted into
// the ExecutionEngine have not yet total difficulty computed.

class ChainForkView {
  public:
    explicit ChainForkView(ChainHead headers_head);

    void reset_head(ChainHead new_head);

    TotalDifficulty add(const BlockHeader&);
    TotalDifficulty add(const BlockHeader&, TotalDifficulty parent_td);

    ChainHead head() const;
    BlockNum head_block_num() const;
    Hash head_hash() const;
    TotalDifficulty head_total_difficulty() const;

    bool head_changed() const;

    std::optional<TotalDifficulty> get_total_difficulty(const Hash& hash);
    std::optional<TotalDifficulty> get_total_difficulty(BlockNum block_num, const Hash& hash);

    static ChainHead head_at_genesis(const ChainConfig& chain_config);

  private:
    ChainHead initial_head_{};
    ChainHead current_head_{};  // current head of the chain

    static constexpr size_t kCacheSize = 4096;
    LruCache<Hash, TotalDifficulty> td_cache_;  // this is not for performance
};

}  // namespace silkworm::chainsync