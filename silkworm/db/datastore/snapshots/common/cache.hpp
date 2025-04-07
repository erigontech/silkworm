// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <utility>

#include <silkworm/core/common/lru_cache.hpp>

#include "key_hasher.hpp"

namespace silkworm::snapshots {

template <typename Value>
class Cache {
  public:
    Cache(size_t size, uint32_t salt) : cache_{size, /*thread_safe=*/true}, key_hasher_{salt} {}

    void put(uint64_t key_hash_high, const Value& value) {
        cache_.put(key_hash_high, value);
    }

    std::optional<Value> get(uint64_t key_hash_high) {
        return cache_.get_as_copy(key_hash_high);
    }

    std::pair<std::optional<Value>, uint64_t> get(ByteView key) {
        const uint64_t hash_high = key_hasher_.hash(key);
        return {get(hash_high), hash_high};
    }

    void clear() noexcept {
        cache_.clear();
    }

  private:
    LruCache<uint64_t, Value> cache_;
    KeyHasher key_hasher_;
};

}  // namespace silkworm::snapshots
