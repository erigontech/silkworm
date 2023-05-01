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

#include <atomic>
#include <cstddef>
#include <functional>
#include <memory>
#include <ostream>
#include <vector>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/concurrency/context_pool.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>

namespace silkworm::rpc {

using ServerCompletionQueuePtr = std::unique_ptr<::grpc::ServerCompletionQueue>;
using ServerCompletionQueueFactory = std::function<ServerCompletionQueuePtr()>;

//! Asynchronous server scheduler running an execution loop w/ integrated gRPC.
class ServerContext :public concurrency::Context {
  public:
    ServerContext(std::size_t context_id, ServerCompletionQueuePtr&& server_queue,
                  concurrency::WaitMode wait_mode = concurrency::WaitMode::blocking);

    [[nodiscard]] agrpc::GrpcContext* server_grpc_context() const noexcept { return server_grpc_context_.get(); }
    [[nodiscard]] agrpc::GrpcContext* client_grpc_context() const noexcept { return client_grpc_context_.get(); }

    //! Execute the scheduler loop until stopped.
    void execute_loop() override;

  private:
    //! Execute back-off loop until stopped.
    void execute_loop_backoff();

    //! Execute single-threaded loop until stopped.
    template <typename WaitStrategy>
    void execute_loop_single_threaded(WaitStrategy&& wait_strategy);

    //! Execute multi-threaded loop until stopped.
    void execute_loop_multi_threaded();

    //! The asio-grpc asynchronous event schedulers.
    std::unique_ptr<agrpc::GrpcContext> server_grpc_context_;
    std::unique_ptr<agrpc::GrpcContext> client_grpc_context_;

    //! The work-tracking executors that keep the asio-grpc scheduler running.
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> server_grpc_context_work_;
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> client_grpc_context_work_;
};

std::ostream& operator<<(std::ostream& out, const ServerContext& c);

//! Pool of \ref ServerContext instances running as separate reactive schedulers.
class ServerContextPool {
  public:
    explicit ServerContextPool(std::size_t pool_size);
    ServerContextPool(
        concurrency::ContextPoolSettings settings,
        const ServerCompletionQueueFactory& queue_factory);
    ~ServerContextPool();

    ServerContextPool(const ServerContextPool&) = delete;
    ServerContextPool& operator=(const ServerContextPool&) = delete;

    //! Add a new \ref ServerContext to the pool.
    void add_context(ServerCompletionQueuePtr queue, concurrency::WaitMode wait_mode);

    //! Start one execution thread for each server context.
    void start() { execution_pool_.start(); }

    //! Wait for termination of all execution threads. This will block until \ref stop() is called.
    void join() { execution_pool_.join(); }

    //! Stop all execution threads. This does *NOT* wait for termination: use \ref join() for that.
    void stop() { execution_pool_.stop(); }

    void run() { execution_pool_.run(); }

    [[nodiscard]] std::size_t num_contexts() const { return execution_pool_.num_contexts(); }

    const ServerContext& next_context() { return static_cast<const ServerContext&>(execution_pool_.next_context()); }

    boost::asio::io_context& next_io_context() { return execution_pool_.next_io_context(); }

  private:
    //! The pool of execution contexts.
    concurrency::ContextPool execution_pool_;
};

}  // namespace silkworm::rpc
