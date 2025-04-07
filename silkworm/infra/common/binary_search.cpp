// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "binary_search.hpp"

namespace silkworm {

size_t binary_find_if(size_t n, absl::FunctionRef<bool(size_t)> f) {
    size_t i{0};
    size_t j{n};
    while (j > i) {
        const size_t count{j - i};
        const size_t m{i + count / 2};
        if (f(m)) {
            j = m;
        } else {
            i = m + 1;
        }
    }
    return i;
}

}  // namespace silkworm
