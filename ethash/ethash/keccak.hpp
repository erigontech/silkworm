// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#pragma once
#ifndef ETHASH_KECCAK_HPP_
#define ETHASH_KECCAK_HPP_

#include <stddef.h>

#include "hash_types.hpp"

#if defined(_MSC_VER)
#include <string.h>
#define __builtin_memcpy memcpy
#endif

namespace ethash {

hash256 keccak256(const uint8_t* input, size_t input_size);
hash256 keccak256(const hash256& input);
hash512 keccak512(const uint8_t* input, size_t input_size);
hash512 keccak512(const hash512& input);

}  // namespace ethash

#endif  // !ETHASH_KECCAK_HPP_
