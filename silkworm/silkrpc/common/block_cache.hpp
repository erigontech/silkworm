/*
   Copyright 2020 The Silkrpc Authors

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
#include <mutex>

#include <evmc/evmc.hpp>
#include <silkworm/core/chain/config.hpp>
#include <silkworm/core/common/util.hpp>
#include <silkworm/core/common/base.hpp>
#include <silkworm/core/execution/address.hpp>
#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/node/db/util.hpp>

#include <boost/compute/detail/lru_cache.hpp>

namespace silkrpc {

class BlockCache {
public:
    explicit BlockCache(std::size_t capacity = 1024, bool shared_cache = true)
        : block_cache_(capacity), shared_cache_(shared_cache) {}

    boost::optional <silkworm::BlockWithHash> get(const evmc::bytes32& key) {
        if (shared_cache_) {
            const std::lock_guard<std::mutex> lock(access_);
            return block_cache_.get(key);
        }
        return block_cache_.get(key);
    }

    void insert(const evmc::bytes32 &key, const silkworm::BlockWithHash& block) {
        if (shared_cache_) {
            const std::lock_guard<std::mutex> lock(access_);
            return block_cache_.insert(key, block);
        }
        block_cache_.insert(key, block);
    }

private:
    mutable std::mutex access_;
    boost::compute::detail::lru_cache<evmc::bytes32, silkworm::BlockWithHash> block_cache_;
    bool shared_cache_;
};

} // namespace silkrpc

