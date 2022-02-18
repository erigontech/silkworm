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

#ifndef SILKWORM_RPC_SERVER_HPP_
#define SILKWORM_RPC_SERVER_HPP_

#include <memory>
#include <mutex>

#include <grpcpp/grpcpp.h>

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server_config.hpp>
#include <silkworm/rpc/server_context_pool.hpp>

namespace silkworm::rpc {

//! Base RPC server able to serve incoming requests for gRPC \ref AsyncService.
template <typename AsyncService>
class Server {
  public:
    //! Build a ready-to-start RPC server according to specified configuration.
    explicit Server(const ServerConfig& config)
    : service_{std::make_unique<AsyncService>()}, context_pool_{config.num_contexts()} {
        SILK_TRACE << "Server::Server " << this << " START";
        grpc::ServerBuilder builder;

        // Disable SO_REUSEPORT socket option to obtain "address already in use" on Windows.
        builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);

        // Add the local endpoint to bind the RPC server to (selected_port will be set *after* BuildAndStart call).
        int selected_port;
        builder.AddListeningPort(config.address_uri(), config.credentials(), &selected_port);

        // Add one server-side gRPC completion queue for each execution context.
        for (std::size_t i{0}; i < config.num_contexts(); ++i) {
            context_pool_.add_context(builder.AddCompletionQueue());
        }

        // Register the service: it must exist for the lifetime of the server built by builder.
        builder.RegisterService(service_.get());

        server_ = builder.BuildAndStart();
        SILK_DEBUG << "Server::Server server bound at selected port: " << selected_port;
        if (server_ == nullptr) {
            SILK_ERROR << "Server::Server " << this << ": BuildAndStart failed [" << config.address_uri() << "]";
            throw std::runtime_error("cannot start gRPC server at " + config.address_uri());
        }
        SILK_TRACE << "Server::Server " << this << " END";
    }

    /// No need to explicitly shutdown the server because this destructor takes care.
    /// Use \ref shutdown() if you want explicit control over termination before destruction.
    virtual ~Server() {
        SILK_TRACE << "Server::~Server " << this << " START";
        shutdown();
        SILK_TRACE << "Server::~Server " << this << " END";
    }

    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    //! Run the RPC server execution loop until \ref shutdown() is called on this Server instance.
    void run() {
        SILK_TRACE << "Server::run " << this << " START";
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (shutdown_) return;

            // gRPC async model requires the server to register one responded call for each RPC in advance.
            SILK_DEBUG << "Server::run " << this << " registering responded calls";
            request_calls();
        }
        // Start the server execution: the context pool loop will block the calling thread.
        SILK_DEBUG << "Server::run " << this << " starting execution loop";
        context_pool_.run();
        SILK_TRACE << "Server::run " << this << " END";
    }

    //! Stop this Server instance forever. Any subsequent call to \ref run() has not effect.
    void shutdown() {
        SILK_TRACE << "Server::shutdown " << this << " START";
        {
            std::lock_guard<std::mutex> guard(mutex_);
            shutdown_ = true;

            // Order matters here: 1) shutdown the server
            server_->Shutdown();

            // Order matters here: 2) shutdown and drain the queues
            context_pool_.stop();
        }
        SILK_TRACE << "Server::shutdown " << this << " END";
    }

    //! Get the next server context in round-robin scheme.
    ServerContext const& next_context() { return context_pool_.next_context(); }

    //! Get the next server scheduler in round-robin scheme.
    boost::asio::io_context& next_io_context() { return context_pool_.next_io_context(); }

  protected:
    //! Subclasses must override this method to register initial server-side RPC requests.
    virtual void request_calls() = 0;

    /// \warning The gRPC service must exist for the lifetime of the gRPC server it is registered on.
    std::unique_ptr<AsyncService> service_;

  private:
    //! gRPC server instance tied to this Server lifetime.
    std::unique_ptr<grpc::Server> server_;

    //! Pool of server schedulers used to run the execution loops.
    ServerContextPool context_pool_;

    //! Mutual exclusion to synchronize run/shutdown operations.
    std::mutex mutex_;

    bool shutdown_{false};
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_SERVER_HPP_
