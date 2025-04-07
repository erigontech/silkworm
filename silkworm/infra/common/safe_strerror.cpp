// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "safe_strerror.hpp"

#include <cstring>

namespace silkworm {

std::string safe_strerror(int err_code) {
    char msg[256];
#if defined(_WIN32)
    if (strerror_s(msg, sizeof(msg), err_code) != 0) {
        (void)strncpy_s(msg, "Unknown error", _TRUNCATE);
    }
#else
    if (strerror_r(err_code, msg, sizeof(msg))) {
        (void)strncpy(msg, "Unknown error", sizeof(msg));
    }
#endif
    msg[sizeof(msg) - 1] = '\0';
    return {msg};
}

}  // namespace silkworm
