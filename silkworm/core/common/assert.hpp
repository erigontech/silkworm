// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

namespace silkworm {
[[noreturn]] void abort_due_to_assertion_failure(char const* expr, char const* file, int line);
}

// SILKWORM_ASSERT always aborts program execution on assertion failure, even when NDEBUG is defined.
#define SILKWORM_ASSERT(expr) \
    if ((expr)) [[likely]]    \
        static_cast<void>(0); \
    else                      \
        ::silkworm::abort_due_to_assertion_failure(#expr, __FILE__, __LINE__)
