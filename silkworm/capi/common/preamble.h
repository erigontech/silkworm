// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_CAPI_PREAMBLE_H_
#define SILKWORM_CAPI_PREAMBLE_H_

#include <stdbool.h>  // NOLINT(*-deprecated-headers)
#include <stddef.h>   // NOLINT(*-deprecated-headers)
#include <stdint.h>   // NOLINT(*-deprecated-headers)

#if defined _MSC_VER
#define SILKWORM_EXPORT __declspec(dllexport)
#else
#define SILKWORM_EXPORT __attribute__((visibility("default")))
#endif

#if __cplusplus
#define SILKWORM_NOEXCEPT noexcept
#else
#define SILKWORM_NOEXCEPT
#endif

#if __cplusplus
extern "C" {
#endif
struct SilkwormInstance;
typedef struct SilkwormInstance* SilkwormHandle;
#if __cplusplus
}
#endif

#include "errors.h"

#define SILKWORM_PATH_SIZE 260

#endif  // SILKWORM_CAPI_PREAMBLE_H_
