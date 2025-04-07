// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

/*  Written in 2018 by David Blackman and Sebastiano Vigna (vigna@acm.org)
To the extent possible under law, the author has dedicated all copyright
and related and neighboring rights to this software to the public domain
worldwide. This software is distributed without any warranty.
See <http://creativecommons.org/publicdomain/zero/1.0/>. */

#pragma once

#include <cstdint>

namespace silkworm::snapshots::rec_split::test_util {

inline uint64_t rotl(const uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

inline uint64_t next_pseudo_random() {
    static uint64_t s[2] = {0x333e2c3815b27604, 0x47ed6e7691d8f09f};

    const uint64_t s0 = s[0];
    uint64_t s1 = s[1];
    const uint64_t result = rotl(s0 + s1, 17) + s0;

    s1 ^= s0;
    s[0] = rotl(s0, 49) ^ s1 ^ (s1 << 21);  // a, b
    s[1] = rotl(s1, 28);                    // c

    return result;
}

}  // namespace silkworm::snapshots::rec_split::test_util
