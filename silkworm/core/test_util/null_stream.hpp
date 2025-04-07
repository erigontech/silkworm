// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <ostream>

namespace silkworm::test_util {

//! Factory function creating one null output stream (all characters are discarded)
inline std::ostream& null_stream() {
    static struct NullBuf : public std::streambuf {
        int overflow(int c) override { return c; }
    } null_buf;
    static struct NullStream : public std::ostream {
        NullStream() : std::ostream(&null_buf) {}
    } null_strm;
    return null_strm;
}

}  // namespace silkworm::test_util
