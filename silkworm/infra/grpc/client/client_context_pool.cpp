/*
   Copyright 2023 The Silkworm Authors

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

#include "client_context_pool.hpp"

#include <exception>
#include <thread>
#include <utility>

#include <magic_enum.hpp>

#include <silkworm/infra/concurrency/idle_strategy.hpp>

namespace silkworm::rpc {

using namespace concurrency;

std::ostream& operator<<(std::ostream& out, const ClientContext& c) {
    out << "io_context: " << c.io_context() << " wait_mode: " << magic_enum::enum_name(c.wait_mode());
    return out;
}

ClientContext::ClientContext(std::size_t context_id, WaitMode wait_mode)
    : Context(context_id, wait_mode),
      grpc_context_{std::make_unique<agrpc::GrpcContext>()},
      grpc_context_work_{boost::asio::make_work_guard(grpc_context_->get_executor())} {}

void ClientContext::execute_loop() {
    switch (wait_mode_) {
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

void ClientContext::execute_loop_backoff() {
    SILK_DEBUG << "Back-off execution loop start [" << std::this_thread::get_id() << "]";
    agrpc::run(*grpc_context_, *io_context_, [&] { return io_context_->stopped(); });
    SILK_DEBUG << "Back-off execution loop end [" << std::this_thread::get_id() << "]";
}

template <typename IdleStrategy>
void ClientContext::execute_loop_single_threaded(IdleStrategy&& idle_strategy) {
    SILK_DEBUG << "Single-thread execution loop start [" << std::this_thread::get_id() << "]";
    while (!io_context_->stopped()) {
        std::size_t work_count = grpc_context_->poll_completion_queue();
        work_count += io_context_->poll();
        std::forward<IdleStrategy>(idle_strategy).idle(work_count);
    }
    SILK_DEBUG << "Single-thread execution loop end [" << std::this_thread::get_id() << "]";
}

void ClientContext::execute_loop_multi_threaded() {
    SILK_DEBUG << "Multi-thread execution loop start [" << std::this_thread::get_id() << "]";
    std::thread grpc_context_thread{[context_id = context_id_, grpc_context = grpc_context_]() {
        log::set_thread_name(("grpc_ctx_s" + std::to_string(context_id)).c_str());
        grpc_context->run_completion_queue();
    }};
    std::exception_ptr run_exception;
    try {
        io_context_->run();
    } catch (...) {
        run_exception = std::current_exception();
    }

    grpc_context_work_.reset();
    grpc_context_->stop();
    grpc_context_thread.join();

    if (run_exception) {
        std::rethrow_exception(run_exception);
    }
    SILK_DEBUG << "Multi-thread execution loop end [" << std::this_thread::get_id() << "]";
}

ClientContextPool::ClientContextPool(std::size_t pool_size, concurrency::WaitMode wait_mode)
    : ContextPool(pool_size) {
    // Create as many execution contexts as required by the pool size
    for (std::size_t i{0}; i < pool_size; ++i) {
        add_context(wait_mode);
    }
}

ClientContextPool::ClientContextPool(concurrency::ContextPoolSettings settings)
    : ClientContextPool(settings.num_contexts, settings.wait_mode) {}

void ClientContextPool::start() {
    // Cannot restart because ::grpc::CompletionQueue inside agrpc::GrpcContext cannot be reused
    if (stopped_) {
        throw std::logic_error("cannot restart context pool, create another one");
    }

    ContextPool<ClientContext>::start();
}

void ClientContextPool::add_context(concurrency::WaitMode wait_mode) {
    const auto context_count = num_contexts();
    const auto& client_context = ContextPool::add_context(ClientContext{context_count, wait_mode});
    SILK_TRACE << "ClientContextPool::add_context context[" << context_count << "] " << client_context;
}

agrpc::GrpcContext& ClientContextPool::any_grpc_context() {
    return *next_context().grpc_context();
}

}  // namespace silkworm::rpc
