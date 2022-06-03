/*
    Copyright 2021 The Silkworm Authors

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

#ifndef SILKWORM_PRIORITY_QUEUE_HPP
#define SILKWORM_PRIORITY_QUEUE_HPP

#include <queue>
#include <set>
#include <vector>

/*
 * A multiset based priority_queue for ease removal of elements
 */
template <typename T, typename CMP>
class set_based_priority_queue {
    using impl_t = std::multiset<T, CMP>;
    impl_t elements_;

  public:
    [[nodiscard]] const T& top() const { return *elements_.begin(); }
    void pop() { elements_.erase(elements_.begin()); }
    void push(const T& element) { elements_.insert(element); }
    void erase(const T& element) { elements_.erase(element); }
    void clear() { elements_.clear(); }
    [[nodiscard]] size_t size() const { return elements_.size(); }
    [[nodiscard]] bool empty() const { return elements_.empty(); }
    [[nodiscard]] bool contains(const T& element) { return elements_.find(element) != elements_.end(); }

    void push_all(const std::vector<T>& source) { for (auto& element: source) push(element); } // bulk insert

    typename impl_t::iterator begin() { return elements_.begin(); }
    typename impl_t::iterator end() { return elements_.end(); }
    typename impl_t::const_iterator begin() const { return elements_.begin(); }
    typename impl_t::const_iterator end() const { return elements_.end(); }
};

/*
 * A custom priority queue that add erase and fix methods to the standard ones
 * For the implementation see here
 * https://stackoverflow.com/questions/19467485/how-to-remove-element-not-at-top-from-priority-queue
 */
template <typename T, typename SEQ = std::vector<T>, typename CMP = std::less<typename SEQ::value_type> >
class heap_based_priority_queue : public std::priority_queue<T, SEQ, CMP> {
  public:
    // erase an element and restore the priority_queue invariant
    bool erase(const T& value) {
        if (auto it = std::find(this->c.begin(), this->c.end(), value); it != this->c.end()) {
            this->c.erase(it);
            std::make_heap(this->c.begin(), this->c.end(), this->comp);
            return true;
        }
        return false;
    }

    // restore the priority_queue invariant (e.g. after an item external modify)
    void fix() { std::make_heap(this->c.begin(), this->c.end(), this->comp); }
};

/*
 * A multimap based priority_queue for ease removal of elements
 *
 * Sample usage:
 *   template <>
 *   struct key<Link> {
 *        using type = BlockNum;
 *        static auto value(const Link& l) -> BlockNum {return l.blockHeight;}
 *   };
 *
 *   map_based_priority_queue<Link, BlockOlderThan> queue;
 */
template <typename T>
struct mbpq_key {
    using type = int;  // type of the key
    static type value(const T&);
};

template <typename T, typename CMP>
class map_based_priority_queue {
    using impl_t = std::multimap<typename mbpq_key<T>::type, T, CMP>;
    impl_t elements_;

  public:
    [[nodiscard]] const T& top() const { return elements_.begin()->second; }
    void pop() { elements_.erase(elements_.begin()); }
    void push(const T& element) { elements_.insert({mbpq_key<T>::value(element), element}); }
    void erase(const T& element) { elements_.erase(mbpq_key<T>::value(element)); }
    [[nodiscard]] size_t size() const { return elements_.size(); }
    [[nodiscard]] bool contains(const T& element) {
        return elements_.find(mbpq_key<T>::value(element)) != elements_.end();
    }

    typename impl_t::iterator begin() { return elements_.begin(); }
    typename impl_t::iterator end() { return elements_.end(); }
    typename impl_t::const_iterator begin() const { return elements_.begin(); }
    typename impl_t::const_iterator end() const { return elements_.end(); }

    // the following is not so beautiful, also it exposes pair used as internal impl
    std::pair<typename impl_t::iterator, typename impl_t::iterator> equal_range(const typename mbpq_key<T>::type& key) {
        return elements_.equal_range(key);
    };
};

/* Note
  Alternative implementation (by greg7mdp)

  using HMap = btree_map<std::pair<BlockNum, Hash>, Link>;

  - ordering:
      sorted first by BlockNum, then by the Hash (default lexicographical comparison by std::pair)
  - lookup:
      map[HMap::key_type(block_number, hash)]
  - erase:
      map.erase(map.begin(), map.lower_bound(HMap::key_type(x,0)));
 */

#endif  // SILKWORM_PRIORITY_QUEUE_HPP
