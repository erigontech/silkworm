// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#ifndef SILKWORM_DB_CAPI_H_
#define SILKWORM_DB_CAPI_H_

#ifdef SILKWORM_CAPI_COMPONENT
#include <silkworm/capi/common/preamble.h>
#else
#include "preamble.h"
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

#if __cplusplus
}
#endif

#endif  // SILKWORM_DB_CAPI_H_
