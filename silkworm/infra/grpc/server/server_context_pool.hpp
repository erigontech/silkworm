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

#include <cstddef>
#include <functional>
#include <memory>

#include <agrpc/asio_grpc.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/concurrency/context_pool.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>

namespace silkworm::rpc {

using ServerCompletionQueuePtr = std::unique_ptr<::grpc::ServerCompletionQueue>;

//! Asynchronous server scheduler running an execution loop w/ integrated gRPC server.
class ServerContext : public concurrency::Context {
  public:
    ServerContext(std::size_t context_id, ServerCompletionQueuePtr server_queue);

    [[nodiscard]] agrpc::GrpcContext* server_grpc_context() const noexcept { return server_grpc_context_.get(); }
    [[nodiscard]] agrpc::GrpcContext* client_grpc_context() const noexcept { return client_grpc_context_.get(); }

    //! Execute the scheduler loop until stopped.
    void execute_loop() override;

  private:
    //! The asio-grpc asynchronous event schedulers.
    std::unique_ptr<agrpc::GrpcContext> server_grpc_context_;
    std::unique_ptr<agrpc::GrpcContext> client_grpc_context_;

    //! The work-tracking executors that keep the asio-grpc scheduler running.
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> server_grpc_context_work_;
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> client_grpc_context_work_;
};

//! Pool of \ref ServerContext instances running as separate reactive schedulers.
class ServerContextPool : public concurrency::ContextPool<ServerContext> {
  public:
    ServerContextPool(
        concurrency::ContextPoolSettings settings,
        grpc::ServerBuilder& server_builder);

    ServerContextPool(const ServerContextPool&) = delete;
    ServerContextPool& operator=(const ServerContextPool&) = delete;
};

}  // namespace silkworm::rpc
