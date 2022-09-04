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
    out << "io_context: " << c.io_context() << " server_queue: " << c.server_queue()
        << " client_queue: " << c.client_queue();
    return out;
}

ServerContext::ServerContext(std::unique_ptr<grpc::ServerCompletionQueue> queue, WaitMode wait_mode)
    : io_context_{std::make_shared<boost::asio::io_context>()},
      work_{boost::asio::require(io_context_->get_executor(), boost::asio::execution::outstanding_work.tracked)},
      server_queue_{std::move(queue)},
      server_end_point_{std::make_unique<CompletionEndPoint>(*server_queue_)},
      client_queue_{std::make_unique<grpc::CompletionQueue>()},
      client_end_point_{std::make_unique<CompletionEndPoint>(*client_queue_)},
      wait_mode_(wait_mode) {}

template <typename WaitStrategy>
void ServerContext::execute_loop_single_threaded(WaitStrategy&& wait_strategy) {
    SILK_DEBUG << "Single-thread execution loop start [" << std::this_thread::get_id() << "]";
    while (!io_context_->stopped()) {
        std::size_t work_count = server_end_point_->poll_one();
        work_count += client_end_point_->poll_one();
        work_count += io_context_->poll_one();
        wait_strategy.idle(static_cast<int>(work_count));
    }
    server_end_point_->shutdown();
    client_end_point_->shutdown();
    SILK_DEBUG << "Single-thread execution loop end [" << std::this_thread::get_id() << "]";
}

void ServerContext::execute_loop_multi_threaded() {
    SILK_DEBUG << "Multi-thread execution loop start [t1=" << std::this_thread::get_id() << "]";
    std::thread server_ep_completion_runner{[&]() {
        SILK_DEBUG << "Server end-point runner start [t2=" << std::this_thread::get_id() << "]";
        bool stopped{false};
        while (!stopped) {
            stopped = server_end_point_->post_one(*io_context_);
        }
        SILK_DEBUG << "Server end-point runner end [t2=" << std::this_thread::get_id() << "]";
    }};
    std::thread client_ep_completion_runner{[&]() {
        SILK_DEBUG << "Client end-point runner start [t3=" << std::this_thread::get_id() << "]";
        bool stopped{false};
        while (!stopped) {
            stopped = client_end_point_->post_one(*io_context_);
        }
        SILK_DEBUG << "Client end-point runner end [t3=" << std::this_thread::get_id() << "]";
    }};
    io_context_->run();
    server_end_point_->shutdown();
    client_end_point_->shutdown();
    server_ep_completion_runner.join();
    client_ep_completion_runner.join();
    SILK_DEBUG << "Multi-thread execution loop end [t1=" << std::this_thread::get_id() << "]";
}

void ServerContext::execute_loop() {
    switch (wait_mode_) {
        case WaitMode::blocking:
            execute_loop_multi_threaded();
            break;
        case WaitMode::yielding:
            execute_loop_single_threaded(YieldingWaitStrategy{});
            break;
        case WaitMode::sleeping:
            execute_loop_single_threaded(SleepingWaitStrategy{});
            break;
        case WaitMode::busy_spin:
            execute_loop_single_threaded(BusySpinWaitStrategy{});
            break;
    }
}

void ServerContext::stop() { io_context_->stop(); }

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

void ServerContextPool::add_context(std::unique_ptr<grpc::ServerCompletionQueue> server_queue, WaitMode wait_mode) {
    ServerContext server_context{std::move(server_queue), wait_mode};

    const auto num_contexts = contexts_.size();
    contexts_.push_back(std::move(server_context));
    SILK_DEBUG << "ServerContextPool::add_context context[" << num_contexts << "] " << contexts_[num_contexts];
}

void ServerContextPool::start() {
    SILK_TRACE << "ServerContextPool::start START";

    if (!stopped_) {
        // Create a pool of threads to run all the contexts (each context having 1 thread)
        for (std::size_t i{0}; i < contexts_.size(); ++i) {
            auto& context = contexts_[i];
            context_threads_.create_thread([&, i = i]() {
                SILK_TRACE << "thread start context[" << i << "] thread_id: " << std::this_thread::get_id();
                context.execute_loop();
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

void ServerContextPool::run() {
    start();
    join();
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

}  // namespace silkworm::rpc
