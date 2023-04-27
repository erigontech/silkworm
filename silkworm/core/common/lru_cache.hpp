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

namespace silkworm {

template <typename key_t, typename value_t>
class lru_cache {
  public:
    typedef typename std::pair<key_t, value_t> key_value_pair_t;
    typedef typename std::list<key_value_pair_t>::iterator list_iterator_t;

    explicit lru_cache(size_t max_size, bool thread_safe = false) : _max_size(max_size), _thread_safe(thread_safe) {}
    void put(const key_t& key, const value_t& value) {
        if (_thread_safe) {
            const std::lock_guard<std::mutex> lock(_access);
            return _put(key, value);
        }
        return _put(key, value);
    }

    const value_t* get(const key_t& key) {
        if (_thread_safe) {
            const std::lock_guard<std::mutex> lock(_access);
            return _get(key);
        }
        return _get(key);
    }

    bool remove(const key_t& key) {
        if (_thread_safe) {
            const std::lock_guard<std::mutex> lock(_access);
            return _remove(key);
        }
        return _remove(key);
    }

    std::optional<value_t> get_as_copy(const key_t& key) {
        auto val = get(key);
        if (val == nullptr) {
            return std::nullopt;
        }
        return {*val};
    }

    void clear() {
        if (_thread_safe) {
            const std::lock_guard<std::mutex> lock(_access);
            _clear();
        }
        _clear();
    }

    [[nodiscard]] size_t size() const noexcept {
        if (_thread_safe) {
            const std::lock_guard<std::mutex> lock(_access);
            return _cache_items_map.size();
        }
        return _cache_items_map.size();
    }

  private:
    void _put(const key_t& key, const value_t& value) {
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

    const value_t* _get(const key_t& key) {
        auto it = _cache_items_map.find(key);
        if (it == _cache_items_map.end()) {
            return nullptr;
        } else {
            _cache_items_list.splice(_cache_items_list.begin(), _cache_items_list, it->second);
            return &(it->second->second);
        }
    }

    bool _remove(const key_t& key) {
        auto it = _cache_items_map.find(key);
        if (it == _cache_items_map.end())
            return false;

        _cache_items_list.erase(it->second);
        _cache_items_map.erase(it);

        return true;
    }

    [[nodiscard]] size_t _size() const noexcept { return _cache_items_map.size(); }

    void _clear() noexcept {
        _cache_items_map.clear();
        _cache_items_list.clear();
    }

  private:
    std::list<key_value_pair_t> _cache_items_list;
    std::unordered_map<key_t, list_iterator_t> _cache_items_map;
    size_t _max_size;
    mutable std::mutex _access;
    bool _thread_safe;
};

}  // namespace silkworm
