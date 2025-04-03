// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

// There is a bug in LLVM's address sanitizer that causes it to report false
// positives when std::logic_error is thrown. This is a workaround
// that disables the check for alloc_dealloc_mismatch.
//
// See also:
// https://github.com/llvm/llvm-project/issues/59432
// https://github.com/google/googletest/issues/4097
// https://github.com/llvm/llvm-project/issues/52771
// https://lists.llvm.org/pipermail/llvm-bugs/2016-August/049095.html

#ifndef __has_feature
// GCC does not have __has_feature, adding it to avoid compilation errors
#define __has_feature(feature) 0
#endif

#if __has_feature(address_sanitizer) || defined(__SANITIZE_ADDRESS__)
#ifdef __cplusplus
extern "C"
#endif
    const char*
    __asan_default_options() {
    return "alloc_dealloc_mismatch=0";
}
#endif
