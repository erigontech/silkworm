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

#include <silkworm/rpc/completion_runner.hpp>

namespace silkworm::rpc {

struct ServerContext {
    std::shared_ptr<boost::asio::io_context> io_context;
    std::unique_ptr<grpc::ServerCompletionQueue> grpc_queue;
    std::unique_ptr<CompletionRunner> grpc_runner;
};

std::ostream& operator<<(std::ostream& out, const ServerContext& c);

class ServerContextPool {
  public:
    explicit ServerContextPool(std::size_t pool_size);
    ~ServerContextPool();

    ServerContextPool(const ServerContextPool&) = delete;
    ServerContextPool& operator=(const ServerContextPool&) = delete;

    void add_context(std::unique_ptr<grpc::ServerCompletionQueue> queue) noexcept;
    void run();
    void stop();

    ServerContext const& next_context();
    boost::asio::io_context& next_io_context();

  private:
    //! The pool of execution contexts.
    std::vector<ServerContext> contexts_;

    //! The work-tracking executors that keep the running contexts.
    std::list<boost::asio::execution::any_executor<>> work_;

    //! The index for obtaining next context to use (round-robin).
    std::size_t next_index_;

    //! Mutual exclusion to synchronize run/stop operations.
    std::mutex mutex_;

    //! Flag indicating if pool has been stopped.
    bool stopped_{false};
};

} // namespace silkworm::rpc

#endif // SILKWORM_RPC_SERVER_CONTEXT_POOL_HPP_
