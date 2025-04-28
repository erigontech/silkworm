// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <optional>
#include <utility>

#include <silkworm/core/common/lru_cache.hpp>

#include "common/key_hasher.hpp"

namespace silkworm::snapshots {

template <typename Value>
class QueryCache {
  public:
    QueryCache(size_t size, KeyHasher key_hasher)
        : cache_{size, /* thread_safe = */ true},
          key_hasher_{std::move(key_hasher)} {}

    void put(uint64_t cache_key, const Value& value) {
        cache_.put(cache_key, value);
    }

    std::optional<Value> get(uint64_t cache_key) {
        return cache_.get_as_copy(cache_key);
    }

    std::pair<std::optional<Value>, uint64_t> get(ByteView key) {
        const uint64_t cache_key = key_hasher_.hash(key);
        return {get(cache_key), cache_key};
    }

    void clear() noexcept {
        cache_.clear();
    }

  private:
    LruCache<uint64_t, Value> cache_;
    KeyHasher key_hasher_;
};

}  // namespace silkworm::snapshots
