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

#ifndef SILKWORM_RPC_SERVER_CONTEXT_POOL_HPP_
#define SILKWORM_RPC_SERVER_CONTEXT_POOL_HPP_

#include <cstddef>
#include <ostream>
#include <list>
#include <memory>
#include <mutex>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/rpc/completion_end_point.hpp>

namespace silkworm::rpc {

class ServerContext {
  public:
    explicit ServerContext(std::unique_ptr<grpc::ServerCompletionQueue> server_queue);

    boost::asio::io_context* io_context() const noexcept { return io_context_.get(); }
    grpc::ServerCompletionQueue* server_queue() const noexcept { return server_queue_.get(); }
    CompletionEndPoint* server_end_point() const noexcept { return server_end_point_.get(); }
    grpc::CompletionQueue* client_queue() const noexcept { return client_queue_.get(); }
    CompletionEndPoint* client_end_point() const noexcept { return client_end_point_.get(); }

    void execution_loop();
    void stop();

  private:
    std::shared_ptr<boost::asio::io_context> io_context_;
    std::unique_ptr<grpc::ServerCompletionQueue> server_queue_;
    std::unique_ptr<CompletionEndPoint> server_end_point_;
    std::unique_ptr<grpc::CompletionQueue> client_queue_;
    std::unique_ptr<CompletionEndPoint> client_end_point_;
};

std::ostream& operator<<(std::ostream& out, const ServerContext& c);

class ServerContextPool {
  public:
    explicit ServerContextPool(std::size_t pool_size);
    ~ServerContextPool();

    ServerContextPool(const ServerContextPool&) = delete;
    ServerContextPool& operator=(const ServerContextPool&) = delete;

    void add_context(std::unique_ptr<grpc::ServerCompletionQueue> queue);

    void start();
    void join();
    void stop();

    std::size_t num_contexts() const { return contexts_.size(); }

    ServerContext const& next_context();
    boost::asio::io_context& next_io_context();

  private:
    //! The pool of execution contexts.
    std::vector<ServerContext> contexts_;

    //! The work-tracking executors that keep the running contexts.
    std::list<boost::asio::execution::any_executor<>> work_;

    //! The pool of threads running the execution contexts.
    boost::asio::detail::thread_group context_threads_;

    //! The index for obtaining next context to use (round-robin).
    std::size_t next_index_;

    //! Mutual exclusion to synchronize run/stop operations.
    std::mutex mutex_;

    //! Flag indicating if pool has been stopped.
    bool stopped_{false};
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_SERVER_CONTEXT_POOL_HPP_
