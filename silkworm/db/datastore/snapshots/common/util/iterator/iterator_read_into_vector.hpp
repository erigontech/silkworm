// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <algorithm>
#include <iterator>
#include <vector>

namespace silkworm {

template <std::input_iterator InputIt>
void iterator_read_into(InputIt it, size_t count, std::vector<typename InputIt::value_type>& out) {
    std::copy_n(std::make_move_iterator(std::move(it)), count, std::back_inserter(out));
}

template <std::input_iterator InputIt>
std::vector<typename InputIt::value_type> iterator_read_into_vector(InputIt it, size_t count) {
    std::vector<typename InputIt::value_type> out;
    out.reserve(count);
    iterator_read_into(std::move(it), count, out);
    return out;
}

}  // namespace silkworm
