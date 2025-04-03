// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

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
        using iterator_category [[maybe_unused]] = std::output_iterator_tag;
        using value_type [[maybe_unused]] = void;
        using difference_type [[maybe_unused]] = std::ptrdiff_t;
        using pointer [[maybe_unused]] = void;
        using reference [[maybe_unused]] = void;

        explicit BackInsertPtrIterator(std::list<T*>& container) : container_(&container) {}

        BackInsertPtrIterator& operator=(T& value) {
            container_->push_back(&value);
            return *this;
        }
        // NOLINTNEXTLINE(cppcoreguidelines-rvalue-reference-param-not-moved)
        BackInsertPtrIterator& operator=(T&&) {  // required to conform to std::output_iterator
            container_->push_back(nullptr);      // but we can't push the temporary's address
            return *this;
        }

        BackInsertPtrIterator& operator*() { return *this; }
        BackInsertPtrIterator& operator++() { return *this; }
        BackInsertPtrIterator operator++(int) { return *this; }

      private:
        std::list<T*>* container_;
    };

    static_assert(std::output_iterator<BackInsertPtrIterator, T>);

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
