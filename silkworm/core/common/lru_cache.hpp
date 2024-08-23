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
    if (_thread_safe) {                   \
        lock = std::unique_lock{_access}; \
    }
#else
#define SILKWORM_LRU_CACHE_GUARD
#endif

template <typename key_t, typename value_t>
class lru_cache {
  public:
    using key_value_pair_t = std::pair<key_t, value_t>;
    using list_iterator_t = std::list<key_value_pair_t>::iterator;

    explicit lru_cache(size_t max_size, bool thread_safe = false) : _max_size(max_size), _thread_safe(thread_safe) {}
    lru_cache(const lru_cache&) = default;
    lru_cache(lru_cache&&) noexcept = default;

    void put(const key_t& key, const value_t& value) {
        SILKWORM_LRU_CACHE_GUARD
        auto it = _cache_items_map.find(key);
        _cache_items_list.push_front(key_value_pair_t(key, value));
        if (it != _cache_items_map.end()) {
            _cache_items_list.erase(it->second);
            _cache_items_map.erase(it);
        }
        _cache_items_map[key] = _cache_items_list.begin();

        if (_cache_items_map.size() > _max_size) {
            auto last = _cache_items_list.end();
            last--;
            _cache_items_map.erase(last->first);
            _cache_items_list.pop_back();
        }
    }

    // this method is not thread-safe. Returns address of the element in the internal map
    const value_t* get(const key_t& key) {
        SILKWORM_ASSERT(_thread_safe == false);
        return _get(key);
    }

    std::optional<value_t> get_as_copy(const key_t& key) {
        SILKWORM_LRU_CACHE_GUARD
        auto val = _get(key);
        if (val == nullptr) {
            return std::nullopt;
        }
        return {*val};
    }

    bool remove(const key_t& key) {
        SILKWORM_LRU_CACHE_GUARD
        auto it = _cache_items_map.find(key);
        if (it == _cache_items_map.end()) {
            return false;
        }

        _cache_items_list.erase(it->second);
        _cache_items_map.erase(it);

        return true;
    }

    [[nodiscard]] size_t size() const noexcept {
        SILKWORM_LRU_CACHE_GUARD
        return _cache_items_map.size();
    }

    [[nodiscard]] size_t max_size() const noexcept {
        return _max_size;
    }

    void clear() noexcept {
        SILKWORM_LRU_CACHE_GUARD
        _cache_items_map.clear();
        _cache_items_list.clear();
    }

  private:
    const value_t* _get(const key_t& key) {
        auto it = _cache_items_map.find(key);
        if (it == _cache_items_map.end()) {
            return nullptr;
        }
        _cache_items_list.splice(_cache_items_list.begin(), _cache_items_list, it->second);
        return &(it->second->second);
    }

    std::list<key_value_pair_t> _cache_items_list;
    std::unordered_map<key_t, list_iterator_t> _cache_items_map;
    size_t _max_size;
    bool _thread_safe;

#ifndef __wasm__
    mutable std::mutex _access;
#endif
};

}  // namespace silkworm
