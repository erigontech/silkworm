// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>

#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>

#include "common/instance.hpp"

namespace silkworm::snapshots {
class SnapshotRepository;
}  // namespace silkworm::snapshots

namespace silkworm::datastore::kvdb {
class DatabaseUnmanaged;
}  // namespace silkworm::datastore::kvdb

struct SilkwormInstance : public capi_todo::SilkwormInstance {
    std::unique_ptr<silkworm::datastore::kvdb::DatabaseUnmanaged> chaindata;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> blocks_repository;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> state_repository_latest;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> state_repository_historical;

    std::optional<silkworm::ChainConfig> chain_config;

    // TODO: This has to be changed and encapsulated by a proper block caching state
    struct ExecutionResult {
        silkworm::TxnId txn_id = 0;
        uint64_t blob_gas_used = 0;
        silkworm::Receipt receipt;
        uint64_t log_index = 0;
    };
    // Keeps all the transactions and receipts created in the current block
    std::vector<ExecutionResult> executions_in_block;
};
