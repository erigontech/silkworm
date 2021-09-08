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
class Set_Based_Priority_Queue {
    std::multiset<T, CMP> elements_;
  public:
    const T& top() const            {return *elements_.begin();}
    void pop()                      {elements_.erase(elements_.begin());}
    void push(const T& element)     {elements_.insert(element);}
    void erase(const T& element)    {elements_.erase(element);}
    size_t size() const             {return elements_.size();}
};

/*
 * A custom priority queue thats add a remove method to the standard one
 * For the implementation see here https://stackoverflow.com/questions/19467485/how-to-remove-element-not-at-top-from-priority-queue
 */
template<typename T, typename SEQ = std::vector<T>,
    typename CMP = std::less<typename SEQ::value_type> >
class custom_priority_queue : public std::priority_queue<T, SEQ, CMP>
{
  public:
    // erase an element and restore the priority_queue invariant
    bool erase(const T& value) {
        auto it = std::find(this->c.begin(), this->c.end(), value);
        if (it != this->c.end()) {
            this->c.erase(it);
            std::make_heap(this->c.begin(), this->c.end(), this->comp);
            return true;
        }
        else {
            return false;
        }
    }

    // restore the priority_queue invariant (e.g. after an item external modify)
    void resort() {
        std::make_heap(this->c.begin(), this->c.end(), this->comp);
    }
};

// todo: add a test for erase & resort

#endif  // SILKWORM_PRIORITY_QUEUE_HPP
