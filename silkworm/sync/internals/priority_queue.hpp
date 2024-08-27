/*
   Copyright 2022 The Silkworm Authors

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

#include <queue>
#include <set>
#include <vector>

/*
 * A set based priority_queue for ease removal of elements
 */
template <typename T, typename CMP = std::less<T>>
class SetBasedPriorityQueue {  // use boost::priority_queue instead?
    using impl_t = std::set<T, CMP>;
    impl_t elements_;

  public:
    [[nodiscard]] const T& top() const { return *elements_.begin(); }
    void pop() { elements_.erase(elements_.begin()); }
    void push(const T& element) { elements_.insert(element); }
    void push(T&& element) { elements_.insert(std::move(element)); }
    size_t erase(const T& element) { return elements_.erase(element); }
    void clear() { elements_.clear(); }
    [[nodiscard]] size_t size() const { return elements_.size(); }
    [[nodiscard]] bool empty() const { return elements_.empty(); }
    [[nodiscard]] bool contains(const T& element) { return elements_.find(element) != elements_.end(); }

    bool update(const T& element, std::function<void(T& element)> apply_change) {
        auto node = elements_.extract(element);
        if (node.empty()) return false;
        apply_change(node.value());
        auto [iter, inserted, n] = elements_.insert(std::move(node));
        return inserted;
    }

    void push_all(const std::vector<T>& source) {
        for (auto& element : source) push(element);
    }  // bulk insert

    typename impl_t::const_iterator begin() const { return elements_.begin(); }
    typename impl_t::const_iterator end() const { return elements_.end(); }
};

/*
 * A multimap based priority_queue for ease removal of elements
 *
 * Sample usage:
 *   template <>
 *   struct key<Link> {
 *        using type = BlockNum;
 *        static BlockNum value(const Link& l) {return l.blockHeight;}
 *   };
 *
 *   MapBasedPriorityQueue<Link, BlockOlderThan> queue;
 */
template <typename T>
struct MbpqKey {
    using type = int;  // type of the key
    static type value(const T&);
};

template <typename T, typename CMP>
class MapBasedPriorityQueue {
    using impl_t = std::multimap<typename MbpqKey<T>::type, T, CMP>;
    impl_t elements_;

  public:
    [[nodiscard]] const T& top() const { return elements_.begin()->second; }
    void pop() { elements_.erase(elements_.begin()); }
    void push(const T& element) { elements_.insert({MbpqKey<T>::value(element), element}); }
    size_t erase(const T& element) { return elements_.erase(MbpqKey<T>::value(element)); }
    [[nodiscard]] size_t size() const { return elements_.size(); }
    [[nodiscard]] size_t empty() const { return elements_.empty(); }
    [[nodiscard]] bool contains(const T& element) { return elements_.find(MbpqKey<T>::value(element)) != elements_.end(); }

    /*typename impl_t::iterator begin() { return elements_.begin(); }
    typename impl_t::iterator end() { return elements_.end(); }*/
    typename impl_t::const_iterator begin() const { return elements_.begin(); }
    typename impl_t::const_iterator end() const { return elements_.end(); }

    // the following is not so beautiful, also it exposes pair used as internal impl
    std::pair<typename impl_t::const_iterator, typename impl_t::const_iterator>
    equal_range(const typename MbpqKey<T>::type& key) { return elements_.equal_range(key); };
};
