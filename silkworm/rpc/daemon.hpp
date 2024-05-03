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

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/thread_pool.hpp>

#include <silkworm/db/mdbx/mdbx.hpp>
#include <silkworm/db/snapshots/repository.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/client_context_pool.hpp>
#include <silkworm/infra/grpc/common/version.hpp>
#include <silkworm/rpc/common/constants.hpp>
#include <silkworm/rpc/ethdb/kv/state_changes_stream.hpp>
#include <silkworm/rpc/http/server.hpp>

#include "settings.hpp"

namespace silkworm::rpc {

struct DaemonInfo {
    std::string build;
    std::string libraries;
};

struct DaemonChecklist {
    std::vector<ProtocolVersionResult> protocol_checklist;

    void success_or_throw() const;
};

class Daemon {
  public:
    static int run(const DaemonSettings& settings, const DaemonInfo& info = {});

    explicit Daemon(DaemonSettings settings, std::optional<mdbx::env> chaindata_env = {});

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

    //! The RPC daemon configuration settings.
    DaemonSettings settings_;

    //! The factory of gRPC client-side channels.
    ChannelFactory create_channel_;

    //! The execution contexts capturing the asynchronous scheduling model.
    ClientContextPool context_pool_;

    //! The pool of workers for long-running tasks.
    boost::asio::thread_pool worker_pool_;

    //! The chaindata MDBX environment or \code std::nullopt if working remotely
    std::optional<mdbx::env> chaindata_env_;

    //! The JSON RPC API services.
    std::vector<std::unique_ptr<http::Server>> rpc_services_;

    //! The gRPC KV interface client stub.
    std::unique_ptr<::remote::KV::StubInterface> kv_stub_;

    //! The stream handling StateChanges server-streaming RPC.
    std::unique_ptr<ethdb::kv::StateChangesStream> state_changes_stream_;

    //! The secret key for communication from CL & EL
    std::optional<std::string> jwt_secret_;
};

}  // namespace silkworm::rpc
