/*
   Copyright 2020 The Silkrpc Authors

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
#include <iostream>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/silkrpc/common/block_cache.hpp>
#include <silkworm/silkrpc/common/log.hpp>
#include <silkworm/silkrpc/concurrency/wait_strategy.hpp>
#include <silkworm/silkrpc/ethbackend/backend.hpp>
#include <silkworm/silkrpc/ethdb/database.hpp>
#include <silkworm/silkrpc/ethdb/kv/state_cache.hpp>
#include <silkworm/silkrpc/txpool/miner.hpp>
#include <silkworm/silkrpc/txpool/transaction_pool.hpp>

namespace silkrpc {

using ChannelFactory = std::function<std::shared_ptr<grpc::Channel>()>;

//! Asynchronous client scheduler running an execution loop.
class Context {
  public:
    explicit Context(
        ChannelFactory create_channel,
        std::shared_ptr<BlockCache> block_cache,
        std::shared_ptr<ethdb::kv::StateCache> state_cache,
        std::shared_ptr<mdbx::env_managed> chaindata_env = {},
        WaitMode wait_mode = WaitMode::blocking);

    boost::asio::io_context* io_context() const noexcept { return io_context_.get(); }
    grpc::CompletionQueue* grpc_queue() const noexcept { return grpc_context_->get_completion_queue(); }
    agrpc::GrpcContext* grpc_context() const noexcept { return grpc_context_.get(); }
    std::unique_ptr<ethdb::Database>& database() noexcept { return database_; }
    std::unique_ptr<ethbackend::BackEnd>& backend() noexcept { return backend_; }
    std::unique_ptr<txpool::Miner>& miner() noexcept { return miner_; }
    std::unique_ptr<txpool::TransactionPool>& tx_pool() noexcept { return tx_pool_; }
    std::shared_ptr<BlockCache>& block_cache() noexcept { return block_cache_; }
    std::shared_ptr<ethdb::kv::StateCache>& state_cache() noexcept { return state_cache_; }

    //! Execute the scheduler loop until stopped.
    void execute_loop();

    //! Stop the execution loop.
    void stop();

  private:
    //! Execute asio-grpc loop until stopped.
    void execute_loop_agrpc();

    //! Execute single-threaded loop until stopped.
    template <typename WaitStrategy>
    void execute_loop_single_threaded(WaitStrategy&& wait_strategy);

    //! Execute multi-threaded loop until stopped.
    void execute_loop_multi_threaded();

    //! The asynchronous event loop scheduler.
    std::shared_ptr<boost::asio::io_context> io_context_;

    //! The work-tracking executor that keep the scheduler running.
    boost::asio::executor_work_guard<boost::asio::io_context::executor_type> io_context_work_;

    std::unique_ptr<agrpc::GrpcContext> grpc_context_;

    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> grpc_context_work_;

    std::unique_ptr<ethdb::Database> database_;
    std::unique_ptr<ethbackend::BackEnd> backend_;
    std::unique_ptr<txpool::Miner> miner_;
    std::unique_ptr<txpool::TransactionPool> tx_pool_;
    std::shared_ptr<BlockCache> block_cache_;
    std::shared_ptr<ethdb::kv::StateCache> state_cache_;
    std::shared_ptr<mdbx::env_managed> chaindata_env_;
    WaitMode wait_mode_;
};

std::ostream& operator<<(std::ostream& out, Context& c);

//! Pool of asynchronous client schedulers.
// [currently cannot start/stop more than once because grpc::CompletionQueue cannot be used after shutdown]
class ContextPool {
public:
    explicit ContextPool(std::size_t pool_size, ChannelFactory create_channel, std::optional<std::string> datadir = {}, WaitMode wait_mode = WaitMode::blocking);
    ~ContextPool();

    ContextPool(const ContextPool&) = delete;
    ContextPool& operator=(const ContextPool&) = delete;

    void start();

    void join();

    void stop();

    void run();

    Context& next_context();

    boost::asio::io_context& next_io_context();

private:
    // The pool of contexts
    std::vector<Context> contexts_;

    //! The pool of threads running the execution contexts.
    boost::asio::detail::thread_group context_threads_;

    // The next index to use for a context
    std::size_t next_index_;

    //! Flag indicating if pool has been stopped.
    bool stopped_{false};
};

} // namespace silkrpc

