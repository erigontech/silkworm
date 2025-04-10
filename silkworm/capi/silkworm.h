// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_H_
#define SILKWORM_H_

// C API exported by Silkworm to be used in Erigon.

#ifdef SILKWORM_CAPI_COMPONENT
#include "common/preamble.h"
#include <silkworm/db/capi/db.h>
#include <silkworm/rpc/capi/rpcdaemon.h>
#include <silkworm/sentry/capi/sentry.h>
#else
#include "preamble.h"
#include "db.h"
#include "rpcdaemon.h"
#include "sentry.h"
#endif
#include "init.h"

#if __cplusplus
extern "C" {
#endif

typedef struct MDBX_env MDBX_env;
typedef struct MDBX_txn MDBX_txn;

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

#if __cplusplus
}
#endif

#endif  // SILKWORM_H_
