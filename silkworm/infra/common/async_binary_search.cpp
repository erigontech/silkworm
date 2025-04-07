// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "async_binary_search.hpp"

namespace silkworm {

Task<size_t> async_binary_search(size_t n, BinaryPredicate pred) {
    size_t i{0};
    size_t j{n};
    while (j > i) {
        const size_t count{j - i};
        const size_t m{i + count / 2};
        if (co_await pred(m)) {
            j = m;
        } else {
            i = m + 1;
        }
    }
    co_return i;
}

}  // namespace silkworm
