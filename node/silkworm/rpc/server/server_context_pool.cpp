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

#include <magic_enum.hpp>

#include <silkworm/common/log.hpp>

namespace silkworm::rpc {

std::ostream& operator<<(std::ostream& out, const ServerContext& c) {
    out << "io_context: " << c.io_context() << " wait_mode: " << magic_enum::enum_name(c.wait_mode());
    return out;
}

inline static std::string build_thread_name(const char name_tag[11], uint32_t id) {
    return {name_tag + std::to_string(id)};
}

ServerContext::ServerContext(std::size_t context_id, std::unique_ptr<grpc::ServerCompletionQueue>&& queue, WaitMode wait_mode)
    : context_id_(context_id),
      io_context_{std::make_shared<boost::asio::io_context>()},
      work_{boost::asio::require(io_context_->get_executor(), boost::asio::execution::outstanding_work_t::tracked)},
      server_grpc_context_{std::make_unique<agrpc::GrpcContext>(std::move(queue))},
      client_grpc_context_{std::make_unique<agrpc::GrpcContext>(std::make_unique<grpc::CompletionQueue>())},
      server_grpc_context_work_{boost::asio::make_work_guard(server_grpc_context_->get_executor())},
      client_grpc_context_work_{boost::asio::make_work_guard(client_grpc_context_->get_executor())},
      wait_mode_(wait_mode) {}

//! Execute asio-grpc loop until stopped.
void ServerContext::execute_loop_agrpc() {
    SILK_DEBUG << "Asio-grpc execution loop start [" << std::this_thread::get_id() << "]";
    boost::asio::post(*io_context_, [&] {
        agrpc::run(*server_grpc_context_, *io_context_, [&] { return io_context_->stopped(); });
    });
    std::thread client_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_c", context_id_).c_str());
        SILK_DEBUG << "Client GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        client_grpc_context_->run_completion_queue();
        SILK_DEBUG << "Client GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};
    io_context_->run();

    client_grpc_context_work_.reset();
    client_grpc_context_->stop();
    client_grpc_context_thread.join();
    SILK_DEBUG << "Asio-grpc execution loop end [" << std::this_thread::get_id() << "]";
}

template <typename WaitStrategy>
void ServerContext::execute_loop_single_threaded(WaitStrategy&& wait_strategy) {
    SILK_DEBUG << "Single-thread execution loop start [" << std::this_thread::get_id() << "]";
    while (!io_context_->stopped()) {
        std::size_t work_count = server_grpc_context_->poll();
        work_count += client_grpc_context_->poll_completion_queue();
        work_count += io_context_->poll();
        wait_strategy.idle(work_count);
    }
    SILK_DEBUG << "Single-thread execution loop end [" << std::this_thread::get_id() << "]";
}

void ServerContext::execute_loop_multi_threaded() {
    SILK_DEBUG << "Multi-thread execution loop start [" << std::this_thread::get_id() << "]";
    std::thread server_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_s", context_id_).c_str());
        SILK_DEBUG << "Server GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        server_grpc_context_->run();
        SILK_DEBUG << "Server GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};
    std::thread client_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_c", context_id_).c_str());
        SILK_DEBUG << "Client GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        client_grpc_context_->run_completion_queue();
        SILK_DEBUG << "Client GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};
    io_context_->run();

    server_grpc_context_work_.reset();
    client_grpc_context_work_.reset();
    client_grpc_context_->stop();
    server_grpc_context_thread.join();
    client_grpc_context_thread.join();
    SILK_DEBUG << "Multi-thread execution loop end [" << std::this_thread::get_id() << "]";
}

void ServerContext::execute_loop() {
    switch (wait_mode_) {
        case WaitMode::backoff:
            execute_loop_agrpc();
            break;
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
    const auto num_contexts = contexts_.size();
    ServerContext server_context{num_contexts, std::move(server_queue), wait_mode};

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
                log::set_thread_name(std::string("asio_ctx_s" + std::to_string(i)).c_str());
                SILK_TRACE << "Thread start context[" << i << "] thread_id: " << std::this_thread::get_id();
                context.execute_loop();
                SILK_TRACE << "Thread end context[" << i << "] thread_id: " << std::this_thread::get_id();
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
