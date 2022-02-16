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

template <typename ServiceType>
class Server {
  public:
    //! Build a ready-to-start RPC server according to specified configuration.
    explicit Server(const ServerConfig& config)
    : service_{std::make_unique<ServiceType>()}, context_pool_{config.num_contexts()} {
        SILK_TRACE << "Server::Server " << this << " START";
        grpc::ServerBuilder builder;
        int selected_port;
        builder.AddChannelArgument(GRPC_ARG_ALLOW_REUSEPORT, 0);
        builder.AddListeningPort(config.address_uri(), config.credentials(), &selected_port);
        for (std::size_t i{0}; i < config.num_contexts(); ++i) {
            context_pool_.add_context(builder.AddCompletionQueue());
        }
        builder.RegisterService(service_.get());
        server_ = builder.BuildAndStart();
        SILK_DEBUG << "Server::Server server started: " << server_.get() << " selected_port: " << selected_port;
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

    void run() {
        SILK_INFO << "Server::run " << this << " START";
        {
            std::unique_lock<std::mutex> lock(mutex_);
            if (shutdown_) return;

            // gRPC async model requires the server to register one responded call for each RPC in advance.
            SILK_DEBUG << "Server::run " << this << " registering responded calls";
            request_calls();

            // Start the server execution: the context pool loop is blocking so release the lock first.
            lock.release()->unlock();
            SILK_DEBUG << "Server::run " << this << " starting execution loop";
            context_pool_.run();
        }
        SILK_INFO << "Server::run " << this << " END";
    }

    void shutdown() {
        SILK_INFO << "Server::shutdown " << this << " START";
        {
            std::lock_guard<std::mutex> guard(mutex_);
            shutdown_ = true;

            // Order matters here: 1) shutdown the server
            server_->Shutdown();

            // Order matters here: 2) shutdown and drain the queues
            context_pool_.stop();
        }
        SILK_INFO << "Server::shutdown " << this << " END";
    }

  protected:
    virtual void request_calls() = 0;

    ServerContext const& next_context() { return context_pool_.next_context(); }

    std::unique_ptr<ServiceType> service_;

  private:
    std::unique_ptr<grpc::Server> server_;
    ServerContextPool context_pool_;

    std::mutex mutex_;

    bool shutdown_{false};
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_SERVER_HPP_
