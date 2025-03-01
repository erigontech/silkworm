/*
   Copyright 2023 The Silkworm Authors

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

#ifndef SILKWORM_H_
#define SILKWORM_H_

// C API exported by Silkworm to be used in Erigon.

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

// Silkworm library error codes (SILKWORM_OK indicates no error, i.e. success)

#define SILKWORM_OK 0
#define SILKWORM_INTERNAL_ERROR 1
#define SILKWORM_UNKNOWN_ERROR 2
#define SILKWORM_INVALID_HANDLE 3
#define SILKWORM_INVALID_PATH 4
#define SILKWORM_INVALID_SNAPSHOT 5
#define SILKWORM_INVALID_MDBX_ENV 6
#define SILKWORM_INVALID_BLOCK_RANGE 7
#define SILKWORM_BLOCK_NOT_FOUND 8
#define SILKWORM_UNKNOWN_CHAIN_ID 9
#define SILKWORM_MDBX_ERROR 10
#define SILKWORM_INVALID_BLOCK 11
#define SILKWORM_DECODING_ERROR 12
#define SILKWORM_TOO_MANY_INSTANCES 13
#define SILKWORM_INVALID_SETTINGS 14
#define SILKWORM_TERMINATION_SIGNAL 15
#define SILKWORM_SERVICE_ALREADY_STARTED 16
#define SILKWORM_INCOMPATIBLE_LIBMDBX 17
#define SILKWORM_INVALID_MDBX_TXN 18

typedef struct MDBX_env MDBX_env;
typedef struct MDBX_txn MDBX_txn;

struct SilkwormInstance;
typedef struct SilkwormInstance* SilkwormHandle;

struct SilkwormMemoryMappedFile {
    const char* file_path;
    uint8_t* memory_address;
    uint64_t memory_length;
};

struct SilkwormHeadersSnapshot {
    struct SilkwormMemoryMappedFile segment;
    struct SilkwormMemoryMappedFile header_hash_index;
};

struct SilkwormBodiesSnapshot {
    struct SilkwormMemoryMappedFile segment;
    struct SilkwormMemoryMappedFile block_num_index;
};

struct SilkwormTransactionsSnapshot {
    struct SilkwormMemoryMappedFile segment;
    struct SilkwormMemoryMappedFile tx_hash_index;
    struct SilkwormMemoryMappedFile tx_hash_2_block_index;
};

struct SilkwormBlocksSnapshotBundle {
    struct SilkwormHeadersSnapshot headers;
    struct SilkwormBodiesSnapshot bodies;
    struct SilkwormTransactionsSnapshot transactions;
};

struct SilkwormInvertedIndexSnapshot {
    struct SilkwormMemoryMappedFile segment;         // .ef
    struct SilkwormMemoryMappedFile accessor_index;  // .efi
};

struct SilkwormHistorySnapshot {
    struct SilkwormMemoryMappedFile segment;         // .v
    struct SilkwormMemoryMappedFile accessor_index;  // .vi
    struct SilkwormInvertedIndexSnapshot inverted_index;
};

struct SilkwormDomainSnapshot {
    struct SilkwormMemoryMappedFile segment;          // .kv
    struct SilkwormMemoryMappedFile existence_index;  // .kvei
    struct SilkwormMemoryMappedFile btree_index;      // .bt
    bool has_accessor_index;
    struct SilkwormMemoryMappedFile accessor_index;  // .kvi
};

struct SilkwormStateSnapshotBundleLatest {
    struct SilkwormDomainSnapshot accounts;
    struct SilkwormDomainSnapshot storage;
    struct SilkwormDomainSnapshot code;
    struct SilkwormDomainSnapshot commitment;
    struct SilkwormDomainSnapshot receipts;
};

struct SilkwormStateSnapshotBundleHistorical {
    struct SilkwormHistorySnapshot accounts;
    struct SilkwormHistorySnapshot storage;
    struct SilkwormHistorySnapshot code;
    struct SilkwormHistorySnapshot receipts;

    struct SilkwormInvertedIndexSnapshot log_addresses;
    struct SilkwormInvertedIndexSnapshot log_topics;
    struct SilkwormInvertedIndexSnapshot traces_from;
    struct SilkwormInvertedIndexSnapshot traces_to;
};

#define SILKWORM_PATH_SIZE 260
#define SILKWORM_GIT_VERSION_SIZE 32

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
 * \brief Build a set of indexes for the given snapshots.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] segments An array of segment files to index.
 * \param[in] len The number of segment files.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure on some or all indexes.
 */
SILKWORM_EXPORT int silkworm_build_recsplit_indexes(SilkwormHandle handle, struct SilkwormMemoryMappedFile* segments[], size_t len) SILKWORM_NOEXCEPT;

/**
 * \brief Notify Silkworm about a new *block* snapshot bundle to use.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] bundle A *block* snapshot bundle to use.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_add_blocks_snapshot_bundle(SilkwormHandle handle, const struct SilkwormBlocksSnapshotBundle* bundle) SILKWORM_NOEXCEPT;

/**
 * \brief Notify Silkworm about a new *latest state* snapshot bundle to use.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] bundle A *latest state* snapshot bundle to use.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_add_state_snapshot_bundle_latest(SilkwormHandle handle, const struct SilkwormStateSnapshotBundleLatest* bundle) SILKWORM_NOEXCEPT;

/**
 * \brief Notify Silkworm about a new *historical state* snapshot bundle to use.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] bundle A *historical state* snapshot bundle to use.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_add_state_snapshot_bundle_historical(SilkwormHandle handle, const struct SilkwormStateSnapshotBundleHistorical* bundle) SILKWORM_NOEXCEPT;

/**
 * \brief Get libmdbx version for compatibility checks.
 * \return A string in git describe format.
 */
SILKWORM_EXPORT const char* silkworm_libmdbx_version(void) SILKWORM_NOEXCEPT;

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
    bool erigon_rpc_compatibility;
    //! Flag indicating if WebSocket support is enabled
    bool ws_enabled;
    //! Flag indicating if compression of WebSocket messages is supported
    bool ws_compression;
    //! Flag indicating if compression of HTTP messages is supported
    bool http_compression;
    //! Flag indicating if version check on internal gRPC protocols should be skipped
    bool skip_internal_protocol_check;
};

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

//! Silkworm Fork Validator configuration options
struct SilkwormForkValidatorSettings {
    size_t batch_size;                    // Batch size to use in stages
    size_t etl_buffer_size;               // Buffer size for ETL operations
    uint32_t sync_loop_throttle_seconds;  // Minimum interval amongst sync cycle
    bool stop_before_senders_stage;       // Stop before senders stage
};

struct SilkwormBytes32 {
    uint8_t bytes[32];
};

/**
 * \brief Start Silkworm fork validator.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] mdbx_env An valid MDBX environment.
 * \param[in] settings The Fork Validator configuration settings.
 */
SILKWORM_EXPORT int silkworm_start_fork_validator(SilkwormHandle handle, MDBX_env* mdbx_env, const struct SilkwormForkValidatorSettings* settings) SILKWORM_NOEXCEPT;

/**
 * \brief Stop Silkworm fork validator.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 */
SILKWORM_EXPORT int silkworm_stop_fork_validator(SilkwormHandle handle) SILKWORM_NOEXCEPT;

#define SILKWORM_FORK_VALIDATOR_ERROR_LENGTH 256
#define SILKWORM_FORK_VALIDATOR_RESULT_STATUS_SUCCESS 0
#define SILKWORM_FORK_VALIDATOR_RESULT_STATUS_BAD_BLOCK 1
#define SILKWORM_FORK_VALIDATOR_RESULT_STATUS_TOO_FAR_AWAY 2
#define SILKWORM_FORK_VALIDATOR_RESULT_STATUS_MISSING_SEGMENT 3
#define SILKWORM_FORK_VALIDATOR_RESULT_STATUS_INVALID 4
#define SILKWORM_FORK_VALIDATOR_RESULT_STATUS_BUSY 5

struct SilkwormForkValidatorValidationResult {
    size_t execution_status;
    struct SilkwormBytes32 last_valid_hash;
    char error_message[SILKWORM_FORK_VALIDATOR_ERROR_LENGTH];
};

/**
 * \brief Verify a chain with the fork validator.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] head_hash_bytes The hash of the head block.
 * \param[out] result The validation result.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_fork_validator_verify_chain(SilkwormHandle handle, struct SilkwormBytes32 head_hash_bytes, struct SilkwormForkValidatorValidationResult* result) SILKWORM_NOEXCEPT;

/**
 * \brief Update the fork choice of the validator.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] head_hash_bytes The hash of the head block.
 * \param[in] finalized_hash_bytes The hash of the finalized block (optional).
 * \param[in] safe_hash_bytes The hash of the safe block (optional).
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_fork_validator_fork_choice_update(SilkwormHandle handle, struct SilkwormBytes32 head_hash_bytes, struct SilkwormBytes32 finalized_hash_bytes, struct SilkwormBytes32 safe_hash_bytes) SILKWORM_NOEXCEPT;

/**
 * \brief Execute a batch of blocks and push changes to the given database transaction. No data is commited.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] txn A valid external read-write MDBX transaction or zero if an internal one must be used.
 * This function does not commit nor abort the transaction.
 * \param[in] chain_id EIP-155 chain ID. SILKWORM_UNKNOWN_CHAIN_ID is returned in case of an unknown or unsupported chain.
 * \param[in] start_block The block number to start the execution from.
 * \param[in] max_block Do not execute after this block.
 * max_block may be executed, or the execution may stop earlier if the batch is full.
 * \param[in] batch_size The size of DB changes to accumulate before returning from this method.
 * Pass 0 if you want to execute just 1 block.
 * \param[in] write_change_sets Whether to write state changes into the DB.
 * \param[in] write_receipts Whether to write CBOR-encoded receipts into the DB.
 * \param[in] write_call_traces Whether to write call traces into the DB.
 * \param[out] last_executed_block The block number of the last successfully executed block.
 * Not written to if no blocks were executed, otherwise *last_executed_block ≤ max_block.
 * \param[out] mdbx_error_code If an MDBX error occurs (this function returns kSilkwormMdbxError)
 * and mdbx_error_code isn't NULL, it's populated with the relevant MDBX error code.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 * SILKWORM_BLOCK_NOT_FOUND is probably OK: it simply means that the execution reached the end of the chain
 * (blocks up to and incl. last_executed_block were still executed).
 */
SILKWORM_EXPORT int silkworm_execute_blocks_ephemeral(
    SilkwormHandle handle, MDBX_txn* txn, uint64_t chain_id, uint64_t start_block, uint64_t max_block,
    uint64_t batch_size, bool write_change_sets, bool write_receipts, bool write_call_traces,
    uint64_t* last_executed_block, int* mdbx_error_code) SILKWORM_NOEXCEPT;

/**
 * \brief Execute a batch of blocks and write resulting changes into the database.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] mdbx_env A valid MDBX environment. Must not be zero.
 * \param[in] chain_id EIP-155 chain ID. SILKWORM_UNKNOWN_CHAIN_ID is returned in case of an unknown or unsupported chain.
 * \param[in] start_block The block number to start the execution from.
 * \param[in] max_block Do not execute after this block.
 * max_block may be executed, or the execution may stop earlier if the batch is full.
 * \param[in] batch_size The size of DB changes to accumulate before returning from this method.
 * Pass 0 if you want to execute just 1 block.
 * \param[in] write_change_sets Whether to write state changes into the DB.
 * \param[in] write_receipts Whether to write CBOR-encoded receipts into the DB.
 * \param[in] write_call_traces Whether to write call traces into the DB.
 * \param[out] last_executed_block The block number of the last successfully executed block.
 * Not written to if no blocks were executed, otherwise *last_executed_block ≤ max_block.
 * \param[out] mdbx_error_code If an MDBX error occurs (this function returns kSilkwormMdbxError)
 * and mdbx_error_code isn't NULL, it's populated with the relevant MDBX error code.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 * SILKWORM_BLOCK_NOT_FOUND is probably OK: it simply means that the execution reached the end of the chain
 * (blocks up to and incl. last_executed_block were still executed).
 */
SILKWORM_EXPORT int silkworm_execute_blocks_perpetual(SilkwormHandle handle, MDBX_env* mdbx_env, uint64_t chain_id,
                                                      uint64_t start_block, uint64_t max_block, uint64_t batch_size,
                                                      bool write_change_sets, bool write_receipts, bool write_call_traces,
                                                      uint64_t* last_executed_block, int* mdbx_error_code) SILKWORM_NOEXCEPT;

/**
 * \brief Execute a transaction in a block.
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] mdbx_tx A valid external read-write MDBX transaction.
 * \param[in] block_num The number of the block containing the transaction.
 * \param[in] block_hash The hash of the block.
 * \param[in] txn_index The transaction number in the block.
 * \param[in] txn_num The canonical transaction ID.
 * \param[out] gas_used The gas used by the transaction.
 * \param[out] blob_gas_used The blob gas used by the transaction.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_execute_txn(SilkwormHandle handle, MDBX_txn* mdbx_tx, uint64_t block_num, struct SilkwormBytes32 block_hash, uint64_t txn_index, uint64_t txn_num, uint64_t* gas_used, uint64_t* blob_gas_used) SILKWORM_NOEXCEPT;

/**
 * \brief Finalize the Silkworm C API library.
 * \param[in] handle A valid Silkworm instance handle got with silkworm_init.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
SILKWORM_EXPORT int silkworm_fini(SilkwormHandle handle) SILKWORM_NOEXCEPT;

#if __cplusplus
}
#endif

#endif  // SILKWORM_H_
