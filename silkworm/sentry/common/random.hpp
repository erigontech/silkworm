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

#include <algorithm>
#include <iterator>
#include <list>
#include <optional>
#include <random>
#include <vector>

#include <silkworm/core/common/base.hpp>
#include <silkworm/core/common/bytes.hpp>

namespace silkworm::sentry {

Bytes random_bytes(Bytes::size_type size);

template <typename T>
std::list<T*> random_list_items(std::list<T>& l, size_t max_count) {
    // an output iterator similar to std::back_insert_iterator,
    // but it inserts pointers to the provided values instead of copying them to the target container
    class BackInsertPtrIterator {
      public:
        [[maybe_unused]] typedef std::output_iterator_tag iterator_category;
        [[maybe_unused]] typedef void value_type;
        [[maybe_unused]] typedef void difference_type;
        [[maybe_unused]] typedef void pointer;
        [[maybe_unused]] typedef void reference;

        explicit BackInsertPtrIterator(std::list<T*>& container) : container_(&container) {}

        BackInsertPtrIterator& operator=(T& value) {
            container_->push_back(&value);
            return *this;
        }
        BackInsertPtrIterator& operator=(T&& value) {
            container_->push_back(&value);
            return *this;
        }

        BackInsertPtrIterator& operator*() { return *this; }
        BackInsertPtrIterator& operator++() { return *this; }
        BackInsertPtrIterator operator++(int) { return *this; }  // NOLINT(cert-dcl21-cpp)

      private:
        std::list<T*>* container_;
    };

    std::list<T*> out;
    std::default_random_engine random_engine{std::random_device{}()};
    std::sample(l.begin(), l.end(), BackInsertPtrIterator(out), max_count, random_engine);
    return out;
}

template <typename T>
std::vector<T> random_vector_items(std::vector<T>& l, size_t max_count) {
    std::vector<T> out;
    std::default_random_engine random_engine{std::random_device{}()};
    std::sample(l.begin(), l.end(), std::back_inserter(out), max_count, random_engine);
    return out;
}

}  // namespace silkworm::sentry
