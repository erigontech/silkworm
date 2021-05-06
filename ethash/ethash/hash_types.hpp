// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

// Modified by Andrea Lanfranchi for Silkworm 2021:
// type aliasing removed

// #pragma once
#ifndef ETHASH_HASH_TYPES_HPP_
#define ETHASH_HASH_TYPES_HPP_

#include <stdint.h>

#include <cstring>

#include "endianess.hpp"

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

#if __BYTE_ORDER == __LITTLE_ENDIAN

struct le {
    static uint32_t uint32(uint32_t x) noexcept { return x; }
    static uint64_t uint64(uint64_t x) noexcept { return x; }

    static const hash1024& uint32s(const hash1024& h) noexcept { return h; }
    static const hash512& uint32s(const hash512& h) noexcept { return h; }
    static const hash256& uint32s(const hash256& h) noexcept { return h; }
};

struct be {
    static uint64_t uint64(uint64_t x) noexcept { return bswap64(x); }
};

#elif __BYTE_ORDER == __BIG_ENDIAN

struct le {
    static uint32_t uint32(uint32_t x) noexcept { return bswap32(x); }
    static uint64_t uint64(uint64_t x) noexcept { return bswap64(x); }

    static hash1024 uint32s(hash1024 h) noexcept {
        for (auto& w : h.word32s) w = uint32(w);
        return h;
    }

    static hash512 uint32s(hash512 h) noexcept {
        for (auto& w : h.word32s) w = uint32(w);
        return h;
    }

    static hash256 uint32s(hash256 h) noexcept {
        for (auto& w : h.word32s) w = uint32(w);
        return h;
    }
};

struct be {
    static uint64_t uint64(uint64_t x) noexcept { return x; }
};

#endif

inline bool is_less_or_equal(const hash256& a, const hash256& b) noexcept {
    for (size_t i{0}; i < (sizeof(a) / sizeof(a.word64s[0])); ++i) {
        if (be::uint64(a.word64s[i]) > be::uint64(b.word64s[i])) return false;
        if (be::uint64(a.word64s[i]) < be::uint64(b.word64s[i])) return true;
    }
    return true;
}

inline bool is_equal(const hash256& a, const hash256& b) { return std::memcmp(a.bytes, b.bytes, sizeof(a)) == 0; }

}  // namespace ethash

#endif  // !ETHASH_HASH_TYPES_HPP_
