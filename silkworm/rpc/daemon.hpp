// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <silkworm/core/chain/config.hpp>
#include <silkworm/db/data_store.hpp>
#include <silkworm/db/datastore/kvdb/mdbx.hpp>
#include <silkworm/db/kv/api/client.hpp>
#include <silkworm/db/kv/state_changes_stream.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/grpc/common/version.hpp>
#include <silkworm/rpc/common/worker_pool.hpp>
#include <silkworm/rpc/http/server.hpp>

#include "settings.hpp"

namespace silkworm::rpc {

struct DaemonChecklist {
    std::vector<ProtocolVersionResult> protocol_checklist;

    void success_or_throw() const;
};

class Daemon {
  public:
    static int run(const DaemonSettings& settings);

    Daemon(
        DaemonSettings settings,
        std::optional<ChainConfig> chain_config,
        std::optional<db::DataStoreRef> data_store);

    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    ClientContextPool& context_pool() { return context_pool_; }

    void add_execution_services(const std::vector<std::shared_ptr<engine::ExecutionEngine>>& engines);

    DaemonChecklist run_checklist();

    void start();
    void stop();

    void join();

  protected:
    static bool validate_settings(const DaemonSettings& settings);
    static ChannelFactory make_channel_factory(const DaemonSettings& settings);

    void add_private_services();
    void add_shared_services();

    std::unique_ptr<db::kv::api::Client> make_kv_client(rpc::ClientContext& context, bool remote);

    //! The RPC daemon configuration settings.
    DaemonSettings settings_;

    //! The chain configuration or std::nullopt if working remotely
    std::optional<ChainConfig> chain_config_;

    //! The factory of gRPC client-side channels.
    ChannelFactory channel_factory_;

    //! The execution contexts capturing the asynchronous scheduling model.
    ClientContextPool context_pool_;

    //! The pool of workers for long-running tasks.
    WorkerPool worker_pool_;

    //! The data store or std::nullopt if working remotely
    std::optional<db::DataStoreRef> data_store_;

    //! The JSON RPC API services.
    std::vector<std::unique_ptr<http::Server>> rpc_services_;

    //! The KV client supporting the state changes stream.
    std::unique_ptr<db::kv::api::Client> state_changes_client_;

    //! The stream handling StateChanges server-streaming RPC.
    std::unique_ptr<db::kv::StateChangesStream> state_changes_stream_;

    //! The secret key for communication from CL & EL
    std::optional<std::string> jwt_secret_;
};

}  // namespace silkworm::rpc
