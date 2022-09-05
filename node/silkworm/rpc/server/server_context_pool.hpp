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
#include <memory>
#include <ostream>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/rpc/completion_end_point.hpp>
#include <silkworm/rpc/server/wait_strategy.hpp>

namespace silkworm::rpc {

//! Asynchronous server scheduler running an execution loop.
class ServerContext {
  public:
    explicit ServerContext(
        std::unique_ptr<grpc::ServerCompletionQueue> server_queue,
        WaitMode wait_mode = WaitMode::blocking);

    boost::asio::io_context* io_context() const noexcept { return io_context_.get(); }
    grpc::ServerCompletionQueue* server_queue() const noexcept { return server_queue_.get(); }
    CompletionEndPoint* server_end_point() const noexcept { return server_end_point_.get(); }
    grpc::CompletionQueue* client_queue() const noexcept { return client_queue_.get(); }
    CompletionEndPoint* client_end_point() const noexcept { return client_end_point_.get(); }

    //! Execute the scheduler loop until stopped.
    void execute_loop();

    //! Stop the execution loop.
    void stop();

  private:
    //! Execute single-threaded loop until stopped.
    template <typename WaitStrategy>
    void execute_loop_single_threaded(WaitStrategy&& wait_strategy);

    //! Execute multi-threaded loop until stopped.
    void execute_loop_multi_threaded();

    //! The asynchronous event loop scheduler.
    std::shared_ptr<boost::asio::io_context> io_context_;

    //! The work-tracking executor that keep the scheduler running.
    boost::asio::execution::any_executor<> work_;

    std::unique_ptr<grpc::ServerCompletionQueue> server_queue_;
    std::unique_ptr<CompletionEndPoint> server_end_point_;
    std::unique_ptr<grpc::CompletionQueue> client_queue_;
    std::unique_ptr<CompletionEndPoint> client_end_point_;

    //! The waiting mode used by execution loops during idle cycles.
    WaitMode wait_mode_;
};

std::ostream& operator<<(std::ostream& out, const ServerContext& c);

//! Pool of \ref ServerContext instances running as separate reactive schedulers.
class ServerContextPool {
  public:
    explicit ServerContextPool(std::size_t pool_size);
    ~ServerContextPool();

    ServerContextPool(const ServerContextPool&) = delete;
    ServerContextPool& operator=(const ServerContextPool&) = delete;

    //! Add a new \ref ServerContext to the pool.
    void add_context(std::unique_ptr<grpc::ServerCompletionQueue> queue, WaitMode wait_mode);

    //! Start one execution thread for each server context.
    void start();

    //! Wait for termination of all execution threads. This will block until \ref stop() is called.
    void join();

    //! Stop all execution threads. This does *NOT* wait for termination: use \ref join() for that.
    void stop();

    void run();

    std::size_t num_contexts() const { return contexts_.size(); }

    ServerContext const& next_context();

    boost::asio::io_context& next_io_context();

  private:
    //! The pool of execution contexts.
    std::vector<ServerContext> contexts_;

    //! The pool of threads running the execution contexts.
    boost::asio::detail::thread_group context_threads_;

    //! The index for obtaining next context to use (round-robin).
    std::size_t next_index_;

    //! Flag indicating if pool has been stopped.
    bool stopped_{false};
};

}  // namespace silkworm::rpc
