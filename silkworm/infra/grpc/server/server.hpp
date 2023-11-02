/*
   Copyright 2022 The Silkworm Authors

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
#include <stdexcept>
#include <utility>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/async_thread.hpp>
#include <silkworm/infra/grpc/server/server_context_pool.hpp>
#include <silkworm/infra/grpc/server/server_settings.hpp>

namespace silkworm::rpc {

//! Base RPC server able to serve incoming requests for gRPC \ref AsyncService instances.
class Server {
  public:
    //! Build a ready-to-start RPC server according to specified configuration.
    explicit Server(ServerSettings settings)
        : settings_{std::move(settings)}, context_pool_{settings_.context_pool_settings.num_contexts} {}

    /**
     * No need to explicitly shutdown the server because this destructor takes care.
     * Use \ref shutdown() if you want explicit control over termination before destruction.
     */
    virtual ~Server() {
        SILK_TRACE << "Server::~Server " << this << " START";
        shutdown();
        SILK_TRACE << "Server::~Server " << this << " END";
    }

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    //! Build the RPC server according to its configuration.
    void build_and_start() {
        SILK_TRACE << "Server::build_and_start " << this << " START";

        if (shutdown_) {
            SILK_TRACE << "Server::build_and_start " << this << " already shut down END";
            return;
        }

        grpc::ServerBuilder builder;

        // Disable SO_REUSEPORT socket option to obtain "address already in use" on Windows.
        builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);

        // Add the local endpoint to bind the RPC server to (selected_port will be set *after* BuildAndStart call).
        int selected_port;
        builder.AddListeningPort(settings_.address_uri, settings_.credentials, &selected_port);

        // Add one server-side gRPC completion queue for each execution context.
        for (std::size_t i{0}; i < settings_.context_pool_settings.num_contexts; ++i) {
            context_pool_.add_context(builder.AddCompletionQueue(), settings_.context_pool_settings.wait_mode);
        }

        // gRPC async model requires the server to register the RPC services first.
        SILK_TRACE << "Server " << this << " registering async services";
        register_async_services(builder);

        server_ = builder.BuildAndStart();
        SILK_TRACE << "Server " << this << " bound at selected port: " << selected_port;
        if (server_ == nullptr) {
            SILK_ERROR << "Server " << this << " BuildAndStart failed. Cannot start gRPC server at [" << settings_.address_uri << "] Port is probably in use!";
            throw std::runtime_error("cannot start gRPC server at " + settings_.address_uri);
        }

        // gRPC async model requires the server to register one request call for each RPC in advance.
        SILK_TRACE << "Server " << this << " registering request calls";
        register_request_calls();

        // Start the server execution: the context pool will spawn the context threads.
        SILK_TRACE << "Server " << this << " starting execution loop";
        context_pool_.start();

        SILK_TRACE << "Server::build_and_start " << this << " END";
    }

    //! Join the RPC server execution loop and block until \ref shutdown() is called on this Server instance.
    void join() {
        SILK_TRACE << "Server::join " << this << " START";
        context_pool_.join();
        SILK_TRACE << "Server::join " << this << " END";
    }

    //! Stop this Server instance forever. Any subsequent call to \ref build_and_start() has not effect.
    void shutdown() {
        SILK_TRACE << "Server::shutdown " << this << " START";

        if (shutdown_) {
            SILK_TRACE << "Server::shutdown " << this << " already shut down END";
            return;
        }
        shutdown_ = true;

        SILK_TRACE << "Server::shutdown " << this << " shutting down server immediately";

        // Order matters here: 1) shutdown the server (immediate deadline)
        if (server_) {
            server_->Shutdown(gpr_time_0(GPR_CLOCK_REALTIME));
            server_->Wait();
        }

        SILK_TRACE << "Server::shutdown " << this << " stopping context pool";

        // Order matters here: 2) shutdown and drain the queues
        context_pool_.stop();

        SILK_TRACE << "Server::shutdown " << this << " END";
    }

    Task<void> async_run(const char* thread_name) {
        auto run = [this] {
            this->build_and_start();
            this->join();
        };
        auto stop = [this] { this->shutdown(); };
        co_await concurrency::async_thread(std::move(run), std::move(stop), thread_name);
    }

    //! Returns the number of server contexts.
    [[nodiscard]] std::size_t num_contexts() const { return context_pool_.num_contexts(); }

    //! Get the next server context in round-robin scheme.
    ServerContext const& next_context() { return context_pool_.next_context(); }

    //! Get the next server scheduler in round-robin scheme.
    boost::asio::io_context& next_io_context() { return context_pool_.next_io_context(); }

  protected:
    //! Subclasses must override this method to register gRPC RPC services into the server.
    virtual void register_async_services(grpc::ServerBuilder& builder) = 0;

    //! Subclasses must override this method to register initial server-side RPC requests.
    virtual void register_request_calls() = 0;

  private:
    //! The server configuration options.
    ServerSettings settings_;

    //! The gRPC server instance tied to this Server lifetime.
    std::unique_ptr<grpc::Server> server_;

    //! Pool of server schedulers used to run the execution loops.
    ServerContextPool context_pool_;

    bool shutdown_{false};
};

}  // namespace silkworm::rpc
