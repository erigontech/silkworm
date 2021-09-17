/* This is CMake-template for libmdbx's version.c
 ******************************************************************************/

#include "internals.h"

#if MDBX_VERSION_MAJOR != 0 ||                             \
    MDBX_VERSION_MINOR != 10
#error "API version mismatch! Had `git fetch --tags` done?"
#endif

static const char sourcery[] = MDBX_STRINGIFY(MDBX_BUILD_SOURCERY);

__dll_export
#ifdef __attribute_used__
    __attribute_used__
#elif defined(__GNUC__) || __has_attribute(__used__)
    __attribute__((__used__))
#endif
#ifdef __attribute_externally_visible__
        __attribute_externally_visible__
#elif (defined(__GNUC__) && !defined(__clang__)) ||                            \
    __has_attribute(__externally_visible__)
    __attribute__((__externally_visible__))
#endif
    const struct MDBX_version_info mdbx_version = {
        0,
        10,
        2,
        0,
        {"2021-07-26T05:23:52+03:00", "3db98a1d3d2364d8cb260df82f1150932547e4b9", "70933d81a86128d6a6f14d7102a9544e4f1807b2",
         "v0.10.2-0-g70933d8"},
        sourcery};

__dll_export
#ifdef __attribute_used__
    __attribute_used__
#elif defined(__GNUC__) || __has_attribute(__used__)
    __attribute__((__used__))
#endif
#ifdef __attribute_externally_visible__
        __attribute_externally_visible__
#elif (defined(__GNUC__) && !defined(__clang__)) ||                            \
    __has_attribute(__externally_visible__)
    __attribute__((__externally_visible__))
#endif
    const char *const mdbx_sourcery_anchor = sourcery;
