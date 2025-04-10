// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>

#include <silkworm/capi/silkworm.h>

int main(int argc, char* argv[]) {
    (void)argc, (void)argv;
#if defined(_MSC_VER)
    printf("MSVC version: %d\n", _MSC_FULL_VER);
#elif defined(__GNUC__) && !defined(__clang__)
    printf("gcc version: %d.%d.%d\n", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
    printf("AppleClang version: %d.%d.%d\n", __clang_major__, __clang_minor__, __clang_patchlevel__);
#endif
    printf("C API silkworm_libmdbx_version: %s\n", silkworm_libmdbx_version());
    return 0;
}
