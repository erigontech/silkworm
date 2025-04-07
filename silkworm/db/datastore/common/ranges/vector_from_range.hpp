// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <iterator>
#include <ranges>
#include <vector>

namespace silkworm {

template <std::ranges::input_range Range, typename Value = std::iter_value_t<std::ranges::iterator_t<Range>>>
std::vector<Value> vector_from_range(Range&& range) {
    std::vector<Value> results;
    for (auto&& value : range) {
        results.emplace_back(std::move(value));
    }
    return results;
}

template <std::ranges::input_range Range, typename Value = std::iter_value_t<std::ranges::iterator_t<Range>>>
std::vector<Value> vector_from_range_copy(Range&& range) {
    std::vector<Value> results;
    std::ranges::copy(range, std::back_inserter(results));
    return results;
}

}  // namespace silkworm
