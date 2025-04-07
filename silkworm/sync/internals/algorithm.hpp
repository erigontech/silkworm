// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <stack>
#include <vector>

// move (non copy) elements from a source container appending them to destination container
template <typename T>
auto move_at_end(std::vector<T>& destination, std::vector<T>& source) {
    destination.insert(destination.end(), std::make_move_iterator(source.begin()),
                       std::make_move_iterator(source.end()));
}

// bulk insert for stacks
template <typename T>
void push_all(std::stack<T>& destination, std::vector<T>& source) {
    for (auto& element : source) destination.push(element);
}
