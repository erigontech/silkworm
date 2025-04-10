// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_RPCDAEMON_CAPI_H_
#define SILKWORM_RPCDAEMON_CAPI_H_

#ifdef SILKWORM_CAPI_COMPONENT
#include <silkworm/capi/common/preamble.h>
#else
#include "preamble.h"
#endif

#if __cplusplus
extern "C" {
#endif

#define SILKWORM_RPC_SETTINGS_HOST_SIZE 128
#define SILKWORM_RPC_SETTINGS_API_NAMESPACE_SPEC_SIZE 256
#define SILKWORM_RPC_SETTINGS_CORS_DOMAINS_MAX 20
#define SILKWORM_RPC_SETTINGS_CORS_DOMAIN_SIZE 256

//! Silkworm RPC interface log options
struct SilkwormRpcInterfaceLogSettings {
    bool enabled;
    char container_folder[SILKWORM_PATH_SIZE];
    uint16_t max_file_size_mb;
    uint16_t max_files;
    bool dump_response;
};

//! Silkworm RPC configuration options
struct SilkwormRpcSettings {
    //! Configuration options for interface log of ETH JSON-RPC end-point
    struct SilkwormRpcInterfaceLogSettings eth_if_log_settings;
    //! Host address for ETH JSON-RPC end-point
    char eth_api_host[SILKWORM_RPC_SETTINGS_HOST_SIZE];
    //! Listening port number for ETH JSON-RPC end-point
    uint16_t eth_api_port;
    //! ETH JSON-RPC namespace specification (comma-separated list of API namespaces)
    char eth_api_spec[SILKWORM_RPC_SETTINGS_API_NAMESPACE_SPEC_SIZE];
    //! Number of threads in worker pool (for long-run tasks)
    uint32_t num_workers;
    //! Array of CORS domains
    char cors_domains[SILKWORM_RPC_SETTINGS_CORS_DOMAINS_MAX][SILKWORM_RPC_SETTINGS_CORS_DOMAIN_SIZE];
    //! Path to the JWT file in UTF-8.
    char jwt_file_path[SILKWORM_PATH_SIZE];
    //! Flag indicating if JSON-RPC strict compatibility w/ Erigon is supported
    bool erigon_json_rpc_compatibility;
    //! Flag indicating if WebSocket support is enabled
    bool ws_enabled;
    //! Flag indicating if compression of WebSocket messages is supported
    bool ws_compression;
    //! Flag indicating if compression of HTTP messages is supported
    bool http_compression;
    //! Flag indicating if version check on internal gRPC protocols should be skipped
    bool skip_internal_protocol_check;
};

typedef struct MDBX_env MDBX_env;

/**
 * \brief Start Silkworm RPC daemon.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init. Must not be zero.
 * \param[in] env An valid MDBX environment. Must not be zero.
 * \param[in] settings The RPC daemon configuration settings. Must not be zero.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_start_rpcdaemon(SilkwormHandle handle, MDBX_env* env, const struct SilkwormRpcSettings* settings) SILKWORM_NOEXCEPT;

/**
 * \brief Stop Silkworm RPC daemon and wait for its termination.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init. Must not be zero.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_stop_rpcdaemon(SilkwormHandle handle) SILKWORM_NOEXCEPT;


#if __cplusplus
}
#endif

#endif  // SILKWORM_RPCDAEMON_CAPI_H_
