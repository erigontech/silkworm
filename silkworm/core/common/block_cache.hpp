// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <memory>

#include <evmc/evmc.hpp>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/lru_cache.hpp>
#include <silkworm/core/types/block.hpp>

namespace silkworm {

class BlockCache {
  public:
    explicit BlockCache(size_t capacity = 1024, bool shared_cache = true)
        : block_cache_(capacity, shared_cache) {}

    std::shared_ptr<BlockWithHash> get(const evmc::bytes32& key) {
        auto result = block_cache_.get_as_copy(key);
        if (result) {
            return *result;
        }
        return nullptr;
    }

    void insert(const evmc::bytes32& key, const std::shared_ptr<BlockWithHash>& block) {
        block_cache_.put(key, block);
    }

  private:
    LruCache<evmc::bytes32, std::shared_ptr<BlockWithHash>> block_cache_;
};

}  // namespace silkworm
