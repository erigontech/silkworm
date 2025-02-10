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

#pragma once

#include <filesystem>
#include <memory>
#include <thread>

#include <boost/asio/cancellation_signal.hpp>

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
};
