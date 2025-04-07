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
#include <silkworm/node/common/node_settings.hpp>

namespace silkworm::snapshots {
class SnapshotRepository;
}  // namespace silkworm::snapshots

namespace silkworm::rpc {
class Daemon;
}  // namespace silkworm::rpc

namespace silkworm::stagedsync {
class ExecutionEngine;
}  // namespace silkworm::stagedsync

namespace silkworm::datastore::kvdb {
class DatabaseUnmanaged;
}  // namespace silkworm::datastore::kvdb

struct SilkwormInstance {
    silkworm::log::Settings log_settings;
    silkworm::concurrency::ContextPoolSettings context_pool_settings;
    std::filesystem::path data_dir_path;
    silkworm::NodeSettings node_settings;
    std::unique_ptr<silkworm::datastore::kvdb::DatabaseUnmanaged> chaindata;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> blocks_repository;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> state_repository_latest;
    std::unique_ptr<silkworm::snapshots::SnapshotRepository> state_repository_historical;
    std::unique_ptr<silkworm::rpc::Daemon> rpcdaemon;
    std::unique_ptr<silkworm::stagedsync::ExecutionEngine> execution_engine;

    std::optional<silkworm::ChainConfig> chain_config;

    // sentry
    std::unique_ptr<std::thread> sentry_thread;
    boost::asio::cancellation_signal sentry_stop_signal;

    // TODO: This has to be changed and encapsulated by a proper block caching state
    // Keeps all the receipts created in the current block
    std::vector<silkworm::Receipt> receipts_in_current_block;
    // Keeps all transactions executed in current block
    std::vector<std::pair<silkworm::TxnId, silkworm::Transaction>> transactions_in_current_block;
};
