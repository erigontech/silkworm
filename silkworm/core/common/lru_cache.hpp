/*
Copyright (c) 2014, lamerman
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

* Neither the name of lamerman nor the names of its
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*
 * Author: Alexander Ponomarev
 *
 * Created on June 20, 2013, 5:09 PM
 *
 * Modified by Andrew Ashikhmin
 */

#pragma once

#include <cstddef>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>

#include <silkworm/core/common/assert.hpp>

namespace silkworm {

#ifndef __wasm__
#define SILKWORM_LRU_CACHE_GUARD          \
    std::unique_lock<std::mutex> lock;    \
    if (thread_safe_) {                   \
        lock = std::unique_lock{access_}; \
    }
#else
#define SILKWORM_LRU_CACHE_GUARD
#endif

template <typename key_t, typename value_t>
class LruCache {
  public:
    using key_value_pair_t = std::pair<key_t, value_t>;
    using list_iterator_t = std::list<key_value_pair_t>::iterator;

    explicit LruCache(size_t max_size, bool thread_safe = false) : max_size_(max_size), thread_safe_(thread_safe) {}
    LruCache(const LruCache&) = default;
    LruCache(LruCache&&) noexcept = default;

    void put(const key_t& key, const value_t& value) {
        SILKWORM_LRU_CACHE_GUARD
        auto it = cache_items_map_.find(key);
        cache_items_list_.push_front(key_value_pair_t(key, value));
        if (it != cache_items_map_.end()) {
            cache_items_list_.erase(it->second);
            cache_items_map_.erase(it);
        }
        cache_items_map_[key] = cache_items_list_.begin();

        if (cache_items_map_.size() > max_size_) {
            auto last = cache_items_list_.end();
            --last;
            cache_items_map_.erase(last->first);
            cache_items_list_.pop_back();
        }
    }

    // this method is not thread-safe. Returns address of the element in the internal map
    const value_t* get(const key_t& key) {
        SILKWORM_ASSERT(!thread_safe_);
        return get_internal(key);
    }

    std::optional<value_t> get_as_copy(const key_t& key) {
        SILKWORM_LRU_CACHE_GUARD
        auto val = get_internal(key);
        if (val == nullptr) {
            return std::nullopt;
        }
        return {*val};
    }

    bool remove(const key_t& key) {
        SILKWORM_LRU_CACHE_GUARD
        auto it = cache_items_map_.find(key);
        if (it == cache_items_map_.end()) {
            return false;
        }

        cache_items_list_.erase(it->second);
        cache_items_map_.erase(it);

        return true;
    }

    [[nodiscard]] size_t size() const noexcept {
        SILKWORM_LRU_CACHE_GUARD
        return cache_items_map_.size();
    }

    [[nodiscard]] size_t max_size() const noexcept {
        return max_size_;
    }

    void clear() noexcept {
        SILKWORM_LRU_CACHE_GUARD
        cache_items_map_.clear();
        cache_items_list_.clear();
    }

  private:
    const value_t* get_internal(const key_t& key) {
        auto it = cache_items_map_.find(key);
        if (it == cache_items_map_.end()) {
            return nullptr;
        }
        cache_items_list_.splice(cache_items_list_.begin(), cache_items_list_, it->second);
        return &(it->second->second);
    }

    std::list<key_value_pair_t> cache_items_list_;
    std::unordered_map<key_t, list_iterator_t> cache_items_map_;
    size_t max_size_;
    bool thread_safe_;

#ifndef __wasm__
    mutable std::mutex access_;
#endif
};

}  // namespace silkworm
