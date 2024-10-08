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

#include <cstddef>
#include <functional>
#include <memory>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/concurrency/context_pool.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/grpc/common/grpc_context_pool.hpp>

namespace silkworm::rpc {

using ChannelFactory = std::function<std::shared_ptr<::grpc::Channel>()>;

//! Asynchronous client scheduler running an execution loop w/ integrated gRPC client.
class ClientContext : public concurrency::Context {
  public:
    explicit ClientContext(size_t context_id);

    [[nodiscard]] agrpc::GrpcContext* grpc_context() const noexcept { return grpc_context_.get(); }

    //! Execute the scheduler loop until stopped.
    void execute_loop() override;

  private:
    void destroy_grpc_context();

    //! The asio-grpc asynchronous event scheduler.
    std::shared_ptr<agrpc::GrpcContext> grpc_context_;

    //! The work-tracking executor that keep the asio-grpc scheduler running.
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> grpc_context_work_;

    friend class ClientContextPool;
};

//! Pool of \ref ClientContext instances running as separate reactive schedulers.
//! \warning currently cannot start/stop more than once because ::grpc::CompletionQueue cannot be used after shutdown
class ClientContextPool : public concurrency::ContextPool<ClientContext>, public GrpcContextPool {
  public:
    using concurrency::ContextPool<ClientContext>::ContextPool;
    ~ClientContextPool() override;

    ClientContextPool(const ClientContextPool&) = delete;
    ClientContextPool& operator=(const ClientContextPool&) = delete;

    void start() override;

    [[nodiscard]] agrpc::GrpcContext& any_grpc_context() override;
};

}  // namespace silkworm::rpc
