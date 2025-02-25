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

    std::optional<std::shared_ptr<BlockWithHash>> get(const evmc::bytes32& key) {
        return block_cache_.get_as_copy(key);
    }

    void insert(const evmc::bytes32& key, const std::shared_ptr<BlockWithHash>& block) {
        block_cache_.put(key, block);
    }

  private:
    LruCache<evmc::bytes32, std::shared_ptr<BlockWithHash>> block_cache_;
};

}  // namespace silkworm
