/*
   Copyright 2025 The Silkworm Authors

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

#include <map>
#include <memory>
#include <optional>
#include <utility>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/core/common/lru_cache.hpp>

#include "../common/entity_name.hpp"
#include "common/key_hasher.hpp"

namespace silkworm::snapshots {

class DomainCache {
  public:
    DomainCache(size_t size, uint32_t salt)
        : cache_{size, /*thread_safe=*/true}, key_hasher_{salt} {}

    void put(uint64_t key_hash_high, const BytesOrByteView& value) {
        cache_.put(key_hash_high, value);
    }

    std::optional<BytesOrByteView> get(uint64_t key_hash_high) {
        return cache_.get_as_copy(key_hash_high);
    }

    std::pair<std::optional<BytesOrByteView>, uint64_t> get(ByteView key) {
        const uint64_t hash_high = key_hasher_.hash(key);
        return {get(hash_high), hash_high};
    }

    void clear() noexcept {
        cache_.clear();
    }

  private:
    LruCache<uint64_t, BytesOrByteView> cache_;
    KeyHasher key_hasher_;
};

using DomainCaches = std::map<datastore::EntityName, std::unique_ptr<DomainCache>>;

}  // namespace silkworm::snapshots
