// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <filesystem>
#include <memory>
#include <thread>

#include <boost/asio/cancellation_signal.hpp>

#include <silkworm/core/types/receipt.hpp>
#include <silkworm/core/types/transaction.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>

namespace silkworm::snapshots {
class SnapshotRepository;
}  // namespace silkworm::snapshots

namespace silkworm::rpc {
class Daemon;
}  // namespace silkworm::rpc

namespace silkworm::datastore::kvdb {
class DatabaseUnmanaged;
}  // namespace silkworm::datastore::kvdb

struct SilkwormInstance {
    silkworm::log::Settings log_settings;
    silkworm::concurrency::ContextPoolSettings context_pool_settings;
    std::filesystem::path data_dir_path;
    std::unique_ptr<silkworm::datastore::kvdb::DatabaseUnmanaged> chaindata;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> blocks_repository;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> state_repository_latest;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> state_repository_historical;
    std::unique_ptr<silkworm::rpc::Daemon> rpcdaemon;

    std::optional<silkworm::ChainConfig> chain_config;

    // sentry
    std::unique_ptr<std::thread> sentry_thread;
    boost::asio::cancellation_signal sentry_stop_signal;

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
