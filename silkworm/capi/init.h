// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_CAPI_INIT_H_
#define SILKWORM_CAPI_INIT_H_

#ifdef SILKWORM_CAPI_COMPONENT
#include "common/preamble.h"
#else
#include "preamble.h"
#endif
#include "log_level.h"

#if __cplusplus
extern "C" {
#endif

#define SILKWORM_GIT_VERSION_SIZE 32

//! Silkworm library general configuration options
struct SilkwormSettings {
    //! Log verbosity level
    SilkwormLogLevel log_verbosity;
    //! Number of I/O contexts to use in concurrency mode
    uint32_t num_contexts;
    //! Data directory path in UTF-8.
    char data_dir_path[SILKWORM_PATH_SIZE];
    //! libmdbx version string in git describe format.
    char libmdbx_version[SILKWORM_GIT_VERSION_SIZE];
    //! Index salt for block snapshots
    uint32_t blocks_repo_index_salt;
    //! Index salt for state snapshots
    uint32_t state_repo_index_salt;
};

/**
 * \brief Initialize the Silkworm C API library.
 * \param[in,out] handle Silkworm instance handle returned on successful initialization.
 * \param[in] settings General Silkworm settings.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_init(SilkwormHandle* handle, const struct SilkwormSettings* settings) SILKWORM_NOEXCEPT;

/**
 * \brief Finalize the Silkworm C API library.
 * \param[in] handle A valid Silkworm instance handle got with silkworm_init.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_fini(SilkwormHandle handle) SILKWORM_NOEXCEPT;

#if __cplusplus
}
#endif

#endif  // SILKWORM_CAPI_INIT_H_
