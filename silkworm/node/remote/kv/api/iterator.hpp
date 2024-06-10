/*
   Copyright 2024 The Silkworm Authors

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

#include <iterator>

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::remote::kv::api {

template <typename T>
    requires(std::is_aggregate_v<T>)
struct Iter {
    explicit Iter(T& entry) : entry_{entry} {}
    ~Iter() = default;

    using difference_type = std::ptrdiff_t;
    using pointer = T*;
    using reference = T&;

    reference operator*() { return entry_; }
    pointer operator->() { return &entry_; }

    Iter<T> operator++(int) { return std::exchange(*this, ++Iter<T>{*this}); }
    Iter<T>& operator++();

    friend bool operator!=(const Iter<T>& lhs, const Iter<T>& rhs) = default;
    friend bool operator==(const Iter<T>& lhs, const Iter<T>& rhs);

  private:
    T& entry_;
};

struct Uint64Iter {
    struct value_type {
        uint64_t value{0};
    };

    explicit Uint64Iter(value_type entry) : entry_{entry} {}
    ~Uint64Iter() = default;

    using difference_type = std::ptrdiff_t;
    using pointer = value_type*;
    using reference = value_type&;

    reference operator*() { return entry_; }
    pointer operator->() { return &entry_; }

    Uint64Iter operator++(int) { return std::exchange(*this, ++Uint64Iter{*this}); }
    Uint64Iter& operator++();

    friend bool operator!=(const Uint64Iter& lhs, const Uint64Iter& rhs) = default;
    friend bool operator==(const Uint64Iter& lhs, const Uint64Iter& rhs);

  private:
    value_type entry_;
};

// static_assert(std::input_or_output_iterator<Uint64Iter>);

struct KeyValueIter {
    struct value_type {
        ByteView key;
        ByteView value;
    };
};

struct KeyValueStepIter {
    struct value_type {
        ByteView key;
        ByteView value;
        uint64_t step{0};
    };
};

template <typename T>
std::vector<T> to_array(Iter<T> it, const Iter<T>& end) {
    std::vector<T> values;
    for (; it != end; ++it) {
        values.push_back(*it);
    }
    return values;
}

using Step = uint64_t;
using StepSequence = std::vector<Step>;
using StepIterator = StepSequence::iterator;

struct KeyValueView {  // TODO(canepat) or use KeyValue?
    ByteView key;
    ByteView value;
};
using KeyValueViewSequence = std::vector<KeyValueView>;
using KeyValueViewIterator = KeyValueViewSequence::iterator;

struct KeyValueAndStep : KeyValueView {
    uint64_t step{0};
};
using KeyValueAndStepSequence = std::vector<KeyValueAndStep>;
using KeyValueAndStepIterator = KeyValueAndStepSequence::iterator;

}  // namespace silkworm::remote::kv::api
