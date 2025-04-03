// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <atomic>
#include <concepts>
#include <set>
#include <variant>
#include <vector>

#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>
#include <silkworm/core/types/block_id.hpp>
#include <silkworm/db/access_layer.hpp>
#include <silkworm/db/stage.hpp>
#include <silkworm/node/stagedsync/execution_pipeline.hpp>

namespace silkworm::stagedsync {

class CanonicalChain {
  public:
    static constexpr size_t kNoCache = 0;

    explicit CanonicalChain(
        db::RWTxn& tx,
        db::DataModelFactory data_model_factory,
        size_t cache_size = kDefaultCacheSize);
    CanonicalChain(CanonicalChain&) = delete;           // tx is not copyable
    CanonicalChain(const CanonicalChain&, db::RWTxn&);  // we can copy a CanonicalChain giving a new tx
    CanonicalChain(CanonicalChain&&) noexcept;

    void open();

    BlockId find_forking_point(Hash header_hash) const;
    BlockId find_forking_point(const BlockHeader& header, Hash header_hash) const;

    void advance(BlockNum block_num, Hash header_hash);
    void update_up_to(BlockNum block_num, Hash hash);
    void delete_down_to(BlockNum unwind_point);
    void set_current_head(BlockId);

    BlockId initial_head() const;
    BlockId current_head() const;

    std::optional<Hash> get_hash(BlockNum block_num) const;
    bool has(Hash block_hash) const;

  private:
    db::DataModel data_model() const { return data_model_factory_(tx_); }

    db::RWTxn& tx_;
    db::DataModelFactory data_model_factory_;

    BlockId initial_head_{};
    BlockId current_head_{};

    static constexpr size_t kDefaultCacheSize = 1000;
    std::unique_ptr<LruCache<BlockNum, Hash>> canonical_hash_cache_;  // uses unique_ptr because LruCache is not movable
    bool cache_enabled() const;
};

}  // namespace silkworm::stagedsync
