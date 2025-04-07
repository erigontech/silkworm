// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "assert.hpp"

#include <cstdlib>
#include <iostream>

namespace silkworm {

void abort_due_to_assertion_failure(char const* expr, char const* file, int line) {
    std::cerr << "Assert failed: " << expr << " Source: " << file << ", line " << line << "\n";
    std::abort();
}

}  // namespace silkworm
