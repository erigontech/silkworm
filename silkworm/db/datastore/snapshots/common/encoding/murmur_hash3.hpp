// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

// MurmurHash3 was written by Austin Appleby, and is placed in the public
// domain. The author hereby disclaims copyright to this source code.

// Platform-specific functions and macros

// Microsoft Visual Studio
#if defined(_MSC_VER) && (_MSC_VER < 1600)
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned __int64 uint64_t;
// Other compilers
#else  // defined(_MSC_VER)
#include <cstdint>
#endif  // !defined(_MSC_VER)

namespace silkworm::snapshots::encoding {

void murmur_hash3_x64_128(const void* key, uint64_t len, uint32_t seed, void* out);

class Murmur3 {
  public:
    explicit Murmur3(uint32_t seed) : seed_(seed) {}

    void reset_seed(uint32_t seed) noexcept {
        seed_ = seed;
    }

    void hash_x64_128(const void* key, uint64_t len, void* out) const {
        murmur_hash3_x64_128(key, len, seed_, out);
    }

  private:
    uint32_t seed_;
};

}  // namespace silkworm::snapshots::encoding
