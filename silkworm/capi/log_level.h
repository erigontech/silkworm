// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_CAPI_LOG_LEVEL_H_
#define SILKWORM_CAPI_LOG_LEVEL_H_

#if __cplusplus
extern "C" {
#endif

//! Silkworm library logging level
//! \note using anonymous C99 enum is the most portable way to pass enum in Cgo
typedef enum {  // NOLINT(performance-enum-size)
    SILKWORM_LOG_NONE,
    SILKWORM_LOG_CRITICAL,
    SILKWORM_LOG_ERROR,
    SILKWORM_LOG_WARNING,
    SILKWORM_LOG_INFO,
    SILKWORM_LOG_DEBUG,
    SILKWORM_LOG_TRACE
} SilkwormLogLevel;

#if __cplusplus
}
#endif

#endif  // SILKWORM_CAPI_LOG_LEVEL_H_
