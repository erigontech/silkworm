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

#include <atomic>
#include <cstddef>
#include <functional>
#include <iostream>
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
    explicit ClientContext(std::size_t context_id, concurrency::WaitMode wait_mode = concurrency::WaitMode::kBlocking);

    [[nodiscard]] agrpc::GrpcContext* grpc_context() const noexcept { return grpc_context_.get(); }

    //! Execute the scheduler loop until stopped.
    void execute_loop() override;

  private:
    void destroy_grpc_context();

    //! Execute back-off loop until stopped.
    void execute_loop_backoff();

    //! Execute single-threaded loop until stopped.
    template <typename IdleStrategy>
    void execute_loop_single_threaded(IdleStrategy&& idle_strategy);

    //! Execute multi-threaded loop until stopped.
    void execute_loop_multi_threaded();

    //! The asio-grpc asynchronous event scheduler.
    std::shared_ptr<agrpc::GrpcContext> grpc_context_;

    //! The work-tracking executor that keep the asio-grpc scheduler running.
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> grpc_context_work_;

    friend class ClientContextPool;
};

std::ostream& operator<<(std::ostream& out, const ClientContext& c);

//! Pool of \ref ClientContext instances running as separate reactive schedulers.
//! \warning currently cannot start/stop more than once because ::grpc::CompletionQueue cannot be used after shutdown
class ClientContextPool : public concurrency::ContextPool<ClientContext>, public GrpcContextPool {
  public:
    explicit ClientContextPool(std::size_t pool_size, concurrency::WaitMode wait_mode = concurrency::WaitMode::kBlocking);
    explicit ClientContextPool(concurrency::ContextPoolSettings settings);
    ~ClientContextPool() override;

    ClientContextPool(const ClientContextPool&) = delete;
    ClientContextPool& operator=(const ClientContextPool&) = delete;

    void start() override;

    //! Add a new \ref ClientContext to the pool.
    void add_context(concurrency::WaitMode wait_mode);

    [[nodiscard]] agrpc::GrpcContext& any_grpc_context() override;
};

}  // namespace silkworm::rpc
