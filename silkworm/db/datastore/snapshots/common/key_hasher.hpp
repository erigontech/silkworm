// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <silkworm/core/common/bytes.hpp>

namespace silkworm::snapshots {

class KeyHasher {
  public:
    explicit KeyHasher(uint32_t salt) : salt_{salt} {}
    uint64_t hash(ByteView key) const;

  private:
    uint32_t salt_;
};

}  // namespace silkworm::snapshots
