// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

// Modified by Andrea Lanfranchi for Silkworm 2021:
// type aliasing removed

// #pragma once
#ifndef ETHASH_HASH_TYPES_HPP_
#define ETHASH_HASH_TYPES_HPP_

#include <stdint.h>

namespace ethash {

union hash256 {
    uint64_t word64s[4];
    uint32_t word32s[8];
    uint8_t bytes[32];
    char str[32];
};

union hash512 {
    uint64_t word64s[8];
    uint32_t word32s[16];
    uint8_t bytes[64];
    char str[64];
};

union hash1024 {
    union hash512 hash512s[2];
    uint64_t word64s[16];
    uint32_t word32s[32];
    uint8_t bytes[128];
    char str[128];
};

union hash2048 {
    union hash512 hash512s[4];
    uint64_t word64s[32];
    uint32_t word32s[64];
    uint8_t bytes[256];
    char str[256];
};

}  // namespace ethash

#endif  // !ETHASH_HASH_TYPES_HPP_
