// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "bloom.hpp"

#include <ethash/keccak.hpp>

#include <silkworm/core/common/util.hpp>

namespace silkworm {

void m3_2048(Bloom& bloom, ByteView x) {
    ethash::hash256 hash{keccak256(x)};
    for (unsigned i{0}; i < 6; i += 2) {
        unsigned bit{static_cast<unsigned>(hash.bytes[i + 1] + (hash.bytes[i] << 8)) & 0x7FFu};
        bloom[kBloomByteLength - 1 - bit / 8] |= 1 << (bit % 8);
    }
}

Bloom logs_bloom(const std::vector<Log>& logs) {
    Bloom bloom{};  // zero initialization
    for (const Log& log : logs) {
        m3_2048(bloom, log.address.bytes);
        for (const auto& topic : log.topics) {
            m3_2048(bloom, topic.bytes);
        }
    }
    return bloom;
}

}  // namespace silkworm
