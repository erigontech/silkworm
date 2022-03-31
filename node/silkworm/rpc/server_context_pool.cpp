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
    out << "io_context: " << c.io_context()
        << " server_queue: " << c.server_queue() << " server_end_point: " << c.server_end_point()
        << " client_queue: " << c.client_queue() << " client_end_point: " << c.client_end_point();
    return out;
}

ServerContext::ServerContext(std::unique_ptr<grpc::ServerCompletionQueue> queue)
    : io_context_{std::make_shared<boost::asio::io_context>()},
    server_queue_{std::move(queue)},
    server_end_point_{std::make_unique<CompletionEndPoint>(*server_queue_)},
    client_queue_{std::make_unique<grpc::CompletionQueue>()},
    client_end_point_{std::make_unique<CompletionEndPoint>(*client_queue_)} {
}

void ServerContext::execution_loop() {
    //TODO(canepat): add counter for served tasks and plug some wait strategy
    while (!io_context_->stopped()) {
        server_end_point_->poll_one();
        client_end_point_->poll_one();
        io_context_->poll_one();
    }
    server_end_point_->shutdown();
    client_end_point_->shutdown();
}

void ServerContext::stop() {
    io_context_->stop();
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
    stop();
    SILK_TRACE << "ServerContextPool::~ServerContextPool END " << this;
}

void ServerContextPool::add_context(std::unique_ptr<grpc::ServerCompletionQueue> server_queue) {
    ServerContext server_context{std::move(server_queue)};

    // Give the io_context work to do so that its event loop will not exit until it is explicitly stopped.
    work_.push_back(boost::asio::require(server_context.io_context()->get_executor(), boost::asio::execution::outstanding_work.tracked));

    const auto num_contexts = contexts_.size();
    contexts_.push_back(std::move(server_context));
    SILK_DEBUG << "ServerContextPool::add_context context[" << num_contexts << "] " << contexts_[num_contexts];
}

void ServerContextPool::start() {
    SILK_TRACE << "ServerContextPool::start START";

    std::unique_lock<std::mutex> lock(mutex_);
    if (!stopped_) {
        // Create a pool of threads to run all the contexts (each context having 1 thread)
        for (std::size_t i{0}; i < contexts_.size(); ++i) {
            auto& context = contexts_[i];
            context_threads_.create_thread([&, i = i]() {
                SILK_TRACE << "thread start context[" << i << "] thread_id: " << std::this_thread::get_id();
                context.execution_loop();
                SILK_TRACE << "thread end context[" << i << "] thread_id: " << std::this_thread::get_id();
            });
            SILK_DEBUG << "ServerContextPool::start context[" << i << "] started: " << context.io_context();
        }
    }

    SILK_TRACE << "ServerContextPool::start END";
}

void ServerContextPool::join() {
    SILK_TRACE << "ServerContextPool::join START";

    // Wait for all threads in the pool to exit.
    SILK_DEBUG << "ServerContextPool::join joining...";
    context_threads_.join();

    SILK_TRACE << "ServerContextPool::join END";
}

void ServerContextPool::stop() {
    SILK_TRACE << "ServerContextPool::stop START";

    std::lock_guard<std::mutex> guard(mutex_);
    if (!stopped_) {
        // Explicitly stop all context runnable components
        for (std::size_t i{0}; i < contexts_.size(); ++i) {
            contexts_[i].stop();
            SILK_DEBUG << "ServerContextPool::stop context[" << i << "] stopped: " << contexts_[i].io_context();
        }

        stopped_ = true;
    }

    SILK_TRACE << "ServerContextPool::stop END";
}

const ServerContext& ServerContextPool::next_context() {
    // Use a round-robin scheme to choose the next context to use
    const auto& context = contexts_[next_index_];
    next_index_ = (next_index_ + 1) % contexts_.size();
    return context;
}

boost::asio::io_context& ServerContextPool::next_io_context() {
    const auto& context = next_context();
    return *context.io_context();
}

} // namespace silkworm::rpc
