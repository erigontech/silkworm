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

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

using namespace concurrency;

std::ostream& operator<<(std::ostream& out, const ServerContext& c) {
    out << "io_context: " << c.io_context() << " wait_mode: " << magic_enum::enum_name(c.wait_mode());
    return out;
}

inline static std::string build_thread_name(const char name_tag[11], size_t id) {
    return {name_tag + std::to_string(id)};
}

ServerContext::ServerContext(std::size_t context_id, ServerCompletionQueuePtr&& queue, concurrency::WaitMode wait_mode)
    : context_{context_id, wait_mode},
      server_grpc_context_{std::make_unique<agrpc::GrpcContext>(std::move(queue))},
      client_grpc_context_{std::make_unique<agrpc::GrpcContext>(std::make_unique<grpc::CompletionQueue>())},
      server_grpc_context_work_{boost::asio::make_work_guard(server_grpc_context_->get_executor())},
      client_grpc_context_work_{boost::asio::make_work_guard(client_grpc_context_->get_executor())} {}

void ServerContext::execute_loop() {
    switch (context_.wait_mode()) {
        case WaitMode::backoff:
            execute_loop_backoff();
            break;
        case WaitMode::blocking:
            execute_loop_multi_threaded();
            break;
        case WaitMode::yielding:
            execute_loop_single_threaded(YieldingIdleStrategy{});
            break;
        case WaitMode::sleeping:
            execute_loop_single_threaded(SleepingIdleStrategy{});
            break;
        case WaitMode::busy_spin:
            execute_loop_single_threaded(BusySpinIdleStrategy{});
            break;
    }
}

//! Execute asio-grpc loop until stopped.
void ServerContext::execute_loop_backoff() {
    SILK_DEBUG << "Back-off execution loop start [" << std::this_thread::get_id() << "]";
    boost::asio::post(*io_context(), [&] {
        agrpc::run(*server_grpc_context_, *io_context(), [&] { return io_context()->stopped(); });
    });
    std::thread client_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_c", id()).c_str());
        SILK_DEBUG << "Client GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        client_grpc_context_->run_completion_queue();
        SILK_DEBUG << "Client GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};
    io_context()->run();

    client_grpc_context_work_.reset();
    client_grpc_context_->stop();
    client_grpc_context_thread.join();
    SILK_DEBUG << "Back-off execution loop end [" << std::this_thread::get_id() << "]";
}

template <typename WaitStrategy>
void ServerContext::execute_loop_single_threaded(WaitStrategy&& wait_strategy) {
    SILK_DEBUG << "Single-thread execution loop start [" << std::this_thread::get_id() << "]";
    while (!io_context()->stopped()) {
        std::size_t work_count = server_grpc_context_->poll();
        work_count += client_grpc_context_->poll_completion_queue();
        work_count += io_context()->poll();
        wait_strategy.idle(work_count);
    }
    SILK_DEBUG << "Single-thread execution loop end [" << std::this_thread::get_id() << "]";
}

void ServerContext::execute_loop_multi_threaded() {
    SILK_DEBUG << "Multi-thread execution loop start [" << std::this_thread::get_id() << "]";
    std::thread server_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_s", id()).c_str());
        SILK_DEBUG << "Server GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        server_grpc_context_->run();
        SILK_DEBUG << "Server GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};
    std::thread client_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_c", id()).c_str());
        SILK_DEBUG << "Client GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        client_grpc_context_->run_completion_queue();
        SILK_DEBUG << "Client GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};
    io_context()->run();

    server_grpc_context_work_.reset();
    client_grpc_context_work_.reset();
    server_grpc_context_->stop();
    client_grpc_context_->stop();
    server_grpc_context_thread.join();
    client_grpc_context_thread.join();
    SILK_DEBUG << "Multi-thread execution loop end [" << std::this_thread::get_id() << "]";
}

ServerContextPool::ServerContextPool(std::size_t pool_size) : execution_pool_{pool_size} {
    if (pool_size == 0) {
        throw std::logic_error("ServerContextPool::ServerContextPool pool_size is 0");
    }
    SILK_INFO << "Creating server context pool with size: " << pool_size;
}

ServerContextPool::ServerContextPool(concurrency::ContextPoolSettings settings,
                                     const ServerCompletionQueueFactory& queue_factory)
    : ServerContextPool(settings.num_contexts) {
    for (size_t i{0}; i < settings.num_contexts; i++) {
        add_context(queue_factory(), settings.wait_mode);
    }
}

ServerContextPool::~ServerContextPool() {
    SILK_TRACE << "ServerContextPool::~ServerContextPool START " << this;
    stop();
    join();
    SILK_TRACE << "ServerContextPool::~ServerContextPool END " << this;
}

void ServerContextPool::add_context(ServerCompletionQueuePtr queue, concurrency::WaitMode wait_mode) {
    const auto num_contexts = execution_pool_.num_contexts();
    const auto& server_context = execution_pool_.add_context(
        {num_contexts, std::move(queue), wait_mode});
    SILK_DEBUG << "ServerContextPool::add_context context[" << num_contexts << "] " << server_context;
}

const ServerContext& ServerContextPool::add_context(ServerContext&& context) {
    return execution_pool_.add_context(std::move(context));
}

}  // namespace silkworm::rpc
