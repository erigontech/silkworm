// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_SENTRY_CAPI_H_
#define SILKWORM_SENTRY_CAPI_H_

#ifdef SILKWORM_CAPI_COMPONENT
#include <silkworm/capi/common/preamble.h>
#else
#include "preamble.h"
#endif

#if __cplusplus
extern "C" {
#endif

#define SILKWORM_SENTRY_SETTINGS_CLIENT_ID_SIZE 128
#define SILKWORM_SENTRY_SETTINGS_NAT_SIZE 50
#define SILKWORM_SENTRY_SETTINGS_NODE_KEY_SIZE 32
#define SILKWORM_SENTRY_SETTINGS_PEERS_MAX 128
#define SILKWORM_SENTRY_SETTINGS_PEER_URL_SIZE 200

//! Silkworm Sentry configuration options
struct SilkwormSentrySettings {
    char client_id[SILKWORM_SENTRY_SETTINGS_CLIENT_ID_SIZE];
    uint16_t api_port;
    uint16_t port;
    char nat[SILKWORM_SENTRY_SETTINGS_NAT_SIZE];
    uint64_t network_id;
    uint8_t node_key[SILKWORM_SENTRY_SETTINGS_NODE_KEY_SIZE];
    char static_peers[SILKWORM_SENTRY_SETTINGS_PEERS_MAX][SILKWORM_SENTRY_SETTINGS_PEER_URL_SIZE];
    char bootnodes[SILKWORM_SENTRY_SETTINGS_PEERS_MAX][SILKWORM_SENTRY_SETTINGS_PEER_URL_SIZE];
    bool no_discover;
    size_t max_peers;
};

/**
 * \brief Start Silkworm Sentry.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.Must not be zero.
 * \param[in] settings The Sentry configuration settings. Must not be zero.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_sentry_start(SilkwormHandle handle, const struct SilkwormSentrySettings* settings) SILKWORM_NOEXCEPT;

/**
 * \brief Stop Silkworm Sentry and wait for its termination.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init. Must not be zero.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_sentry_stop(SilkwormHandle handle) SILKWORM_NOEXCEPT;

#if __cplusplus
}
#endif

#endif  // SILKWORM_SENTRY_CAPI_H_
