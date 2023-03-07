/*
   Copyright 2020 The Silkrpc Authors

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
#include <string>
#include <vector>

#include <boost/asio/thread_pool.hpp>

#include <silkworm/silkrpc/common/constants.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/concurrency/context_pool.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_changes_stream.hpp>
#include <silkworm/silkrpc/http/server.hpp>
#include <silkworm/silkrpc/protocol/version.hpp>

namespace silkrpc {

struct DaemonSettings {
    std::optional<std::string> datadir;
    std::string http_port; // eth_end_point
    std::string engine_port; // engine_end_point
    std::string api_spec; // eth_api_spec
    std::string target; // backend_kv_address
    uint32_t num_contexts;
    uint32_t num_workers;
    LogLevel log_verbosity;
    WaitMode wait_mode;
    std::string jwt_secret_filename;
};

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

    explicit Daemon(const DaemonSettings& settings, const std::string& jwt_secret);

    Daemon(const Daemon&) = delete;
    Daemon& operator=(const Daemon&) = delete;

    DaemonChecklist run_checklist();

    void start();
    void stop();

    void join();

  protected:
    static bool validate_settings(const DaemonSettings& settings);
    static ChannelFactory make_channel_factory(const DaemonSettings& settings);

    //! The RPC daemon configuration settings.
    const DaemonSettings& settings_;

    //! The factory of gRPC client-side channels.
    ChannelFactory create_channel_;

    //! The execution contexts capturing the asynchronous scheduling model.
    ContextPool context_pool_;

    //! The pool of workers for long-running tasks.
    boost::asio::thread_pool worker_pool_;

    std::vector<std::unique_ptr<http::Server>> rpc_services_;

    //! The gRPC KV interface client stub.
    std::unique_ptr<remote::KV::StubInterface> kv_stub_;

    //! The stream handling StateChanges server-streaming RPC.
    std::unique_ptr<ethdb::kv::StateChangesStream> state_changes_stream_;

    //! The secret key for communication from CL & EL
    const std::string& jwt_secret_;
};

} // namespace silkrpc

