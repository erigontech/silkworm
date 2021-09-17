/* This is CMake-template for libmdbx's config.h
 ******************************************************************************/

/* *INDENT-OFF* */
/* clang-format off */

/* #undef LTO_ENABLED */
/* #undef MDBX_USE_VALGRIND */
/* #undef ENABLE_GPROF */
/* #undef ENABLE_GCOV */
/* #undef ENABLE_ASAN */
/* #undef ENABLE_UBSAN */
#define MDBX_FORCE_ASSERTIONS 0

/* Common */
#define MDBX_TXN_CHECKOWNER 1
#define MDBX_ENV_CHECKPID_AUTO
#ifndef MDBX_ENV_CHECKPID_AUTO
#define MDBX_ENV_CHECKPID 0
#endif
#define MDBX_LOCKING_AUTO
#ifndef MDBX_LOCKING_AUTO
/* #undef MDBX_LOCKING */
#endif
#define MDBX_TRUST_RTC_AUTO
#ifndef MDBX_TRUST_RTC_AUTO
#define MDBX_TRUST_RTC 0
#endif
#define MDBX_DISABLE_PAGECHECKS 0

/* Windows */
#define MDBX_WITHOUT_MSVC_CRT 0

/* MacOS & iOS */
#define MDBX_OSX_SPEED_INSTEADOF_DURABILITY 0

/* POSIX */
#define MDBX_DISABLE_GNU_SOURCE 0
#define MDBX_USE_OFDLOCKS_AUTO
#ifndef MDBX_USE_OFDLOCKS_AUTO
#define MDBX_USE_OFDLOCKS 0
#endif

/* Build Info */
#ifndef MDBX_BUILD_TIMESTAMP
#define MDBX_BUILD_TIMESTAMP "2021-09-17T14:37:51Z"
#endif
#ifndef MDBX_BUILD_TARGET
#define MDBX_BUILD_TARGET "x86_64-Darwin"
#endif
#ifndef MDBX_BUILD_TYPE
#define MDBX_BUILD_TYPE "Debug"
#endif
#ifndef MDBX_BUILD_COMPILER
#define MDBX_BUILD_COMPILER "Apple clang version 12.0.0 (clang-1200.0.32.29)"
#endif
#ifndef MDBX_BUILD_FLAGS
#define MDBX_BUILD_FLAGS "-g MDBX_BUILD_SHARED_LIBRARY=0 -ffast-math -fvisibility=hidden"
#endif
#define MDBX_BUILD_SOURCERY cc639d53c5c05bf8650481104ee25a6df111a5af846ea952d84ecd923431f455_v0_10_2_0_g70933d8

/* *INDENT-ON* */
/* clang-format on */
