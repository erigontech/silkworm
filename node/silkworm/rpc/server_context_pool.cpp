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

#include "server_context_pool.hpp"

#include <stdexcept>
#include <thread>
#include <utility>

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const ServerContext& c) {
    out << "io_context: " << &*c.io_context << " grpc_queue: " << &*c.grpc_queue << " grpc_runner: " << &*c.grpc_runner;
    return out;
}

ServerContextPool::ServerContextPool(std::size_t pool_size) : next_index_{0} {
    if (pool_size == 0) {
        throw std::logic_error("ServerContextPool::ServerContextPool pool_size is 0");
    }
    SILK_INFO << "Creating server context pool with size: " << pool_size;

    contexts_.reserve(pool_size);
}

ServerContextPool::~ServerContextPool() {
    SILK_TRACE << "ServerContextPool::~ServerContextPool START " << this;
    if (!stopped_) {
        stop();
    }
    SILK_TRACE << "ServerContextPool::~ServerContextPool END " << this;
}

void ServerContextPool::add_context(std::unique_ptr<grpc::ServerCompletionQueue> queue) noexcept {
    // Create the io_context and give it work to do so that its event loop will not exit until it is explicitly stopped.
    auto io_context = std::make_shared<boost::asio::io_context>();
    auto runner = std::make_unique<CompletionRunner>(*queue, *io_context);
    const auto num_contexts = contexts_.size();
    contexts_.push_back({
        io_context,
        std::move(queue),
        std::move(runner)
    });
    SILK_DEBUG << "ServerContextPool::add_context context[" << num_contexts << "] " << contexts_[num_contexts];
    work_.push_back(boost::asio::require(io_context->get_executor(), boost::asio::execution::outstanding_work.tracked));
}

void ServerContextPool::run() {
    SILK_TRACE << "ServerContextPool::run START";

    boost::asio::detail::thread_group workers{};
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (stopped_) return;

        // Create a pool of threads to run all of the contexts (each one having 1+1 threads)
        for (std::size_t i{0}; i < contexts_.size(); ++i) {
            auto& context = contexts_[i];
            workers.create_thread([&, i = i]() {
                SILK_TRACE << "CompletionRunner thread start context[" << i << "].grpc_runner thread_id: " << std::this_thread::get_id();
                context.grpc_runner->run();
                SILK_TRACE << "CompletionRunner thread end context[" << i << "].grpc_runner thread_id: " << std::this_thread::get_id();
            });
            SILK_DEBUG << "ServerContextPool::run context[" << i << "].grpc_runner started: " << &*context.grpc_runner;
            workers.create_thread([&, i = i]() {
                SILK_TRACE << "io_context thread start context[" << i << "].io_context thread_id: " << std::this_thread::get_id();
                context.io_context->run();
                SILK_TRACE << "io_context thread end context[" << i << "].io_context thread_id: " << std::this_thread::get_id();
            });
            SILK_DEBUG << "ServerContextPool::run context[" << i << "].io_context started: " << &*context.io_context;
        }
    }
    // Wait for all threads in the pool to exit.
    SILK_DEBUG << "ServerContextPool::run joining...";
    workers.join();

    SILK_TRACE << "ServerContextPool::run END";
}

void ServerContextPool::stop() {
    SILK_TRACE << "ServerContextPool::stop START stopped: " << stopped_;

    {
        std::lock_guard<std::mutex> guard(mutex_);
        stopped_ = true;

        // Explicitly stop all context runnable components
        for (std::size_t i{0}; i < contexts_.size(); ++i) {
            auto& context = contexts_[i];
            context.grpc_runner->stop();
            SILK_DEBUG << "ServerContextPool::stop context[" << i << "].grpc_runner stopped: " << &*context.grpc_runner;
            context.io_context->stop();
            SILK_DEBUG << "ServerContextPool::stop context[" << i << "].io_context stopped: " << &*context.io_context;
        }
    }

    SILK_TRACE << "ServerContextPool::stop END stopped: " << stopped_;
}

const ServerContext& ServerContextPool::next_context() {
    // Use a round-robin scheme to choose the next context to use
    const auto& context = contexts_[next_index_];
    next_index_ = (next_index_ + 1) % contexts_.size();
    return context;
}

boost::asio::io_context& ServerContextPool::next_io_context() {
    const auto& context = next_context();
    return *context.io_context;
}

} // namespace silkworm::rpc
