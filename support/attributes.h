// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

#pragma once

// Provide __has_attribute macro if not defined.
#ifndef __has_attribute
#define __has_attribute(name) 0
#endif

// [[always_inline]]
#if _MSC_VER
#define ALWAYS_INLINE __forceinline
#elif __has_attribute(always_inline)
#define ALWAYS_INLINE __attribute__((always_inline))
#else
#define ALWAYS_INLINE
#endif

// [[no_sanitize()]]
#if __clang__
#define NO_SANITIZE(sanitizer) __attribute__((no_sanitize(sanitizer)))
#else
#define NO_SANITIZE(sanitizer)
#endif
