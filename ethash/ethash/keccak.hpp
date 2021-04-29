// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#pragma once
#ifndef ETHASH_KECCAK_HPP_
#define ETHASH_KECCAK_HPP_

#include "hash_types.hpp"
#include <stddef.h>

#if defined(_MSC_VER)
#include <string.h>
#define __builtin_memcpy memcpy
#endif

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define to_le64(X) __builtin_bswap64(X)
#else
#define to_le64(X) X
#endif


namespace ethash {

hash256 keccak256(const uint8_t* input, size_t input_size);
hash256 keccak256(const hash256& input);

}  // namespace ethash

#endif  // !ETHASH_KECCAK_HPP_
