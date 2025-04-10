// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_H_
#define SILKWORM_H_

// C API exported by Silkworm to be used in Erigon.

#ifdef SILKWORM_CAPI_COMPONENT
#include "common/preamble.h"
#include <silkworm/rpc/capi/rpcdaemon.h>
#include <silkworm/sentry/capi/sentry.h>
#else
#include "preamble.h"
#include "rpcdaemon.h"
#include "sentry.h"
#endif

#if __cplusplus
extern "C" {
#endif

typedef struct MDBX_env MDBX_env;
typedef struct MDBX_txn MDBX_txn;

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

struct SilkwormBytes32 {
    uint8_t bytes[32];
};

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
 * \brief Signals starting block execution
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] mdbx_tx A valid external read-write MDBX transaction.
 * \param[in] block_num The number of the block containing the transaction.
 * \param[in] block_hash The hash of the block.
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
 SILKWORM_EXPORT int silkworm_block_exec_start(SilkwormHandle handle, MDBX_txn* mdbx_tx, uint64_t block_num, struct SilkwormBytes32 block_hash) SILKWORM_NOEXCEPT;

/**
 * \brief Signals completing block execution
 * \param[in] handle A valid Silkworm instance handle, got with silkworm_init.
 * \param[in] mdbx_tx A valid external read-write MDBX transaction.
 * \param[in] mdbx_in_mem_temp_tx A valid in memory MDBX transaction for silkworm->erigon communication
 * \return SILKWORM_OK (=0) on success, a non-zero error value on failure.
 */
 SILKWORM_EXPORT int silkworm_block_exec_end(SilkwormHandle handle, MDBX_txn* mdbx_tx, MDBX_txn* mdbx_in_mem_temp_tx) SILKWORM_NOEXCEPT;

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
