// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include <silkworm/core/types/log.hpp>

namespace silkworm {

inline constexpr size_t kBloomByteLength{256};

using Bloom = std::array<uint8_t, kBloomByteLength>;

//! See Section 4.3.1 "Transaction Receipt" of the Yellow Paper
void m3_2048(Bloom& bloom, ByteView x);

Bloom logs_bloom(const std::vector<Log>& logs);

inline void join(Bloom& sum, const Bloom& addend) {
    for (size_t i{0}; i < kBloomByteLength; ++i) {
        sum[i] |= addend[i];
    }
}

inline std::string_view to_string(const Bloom& bloom) {
    return {reinterpret_cast<const char*>(bloom.data()), bloom.size()};
}

}  // namespace silkworm
