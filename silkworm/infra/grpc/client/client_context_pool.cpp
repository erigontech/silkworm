// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "client_context_pool.hpp"

#include <exception>
#include <thread>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

using namespace concurrency;

ClientContext::ClientContext(size_t context_id)
    : Context{context_id},
      grpc_context_{std::make_unique<agrpc::GrpcContext>()},
      grpc_context_work_{boost::asio::make_work_guard(grpc_context_->get_executor())} {}

void ClientContext::destroy_grpc_context() {
    grpc_context_work_.reset();
    grpc_context_.reset();
}

void ClientContext::execute_loop() {
    SILK_DEBUG << "ClientContext execution loop start [" << std::this_thread::get_id() << "]";

    std::thread grpc_context_thread{[context_id = context_id_, grpc_context = grpc_context_]() {
        log::set_thread_name(("grpc_ctx_s" + std::to_string(context_id)).c_str());
        grpc_context->run_completion_queue();
    }};

    std::exception_ptr run_exception;
    try {
        ioc_->run();
    } catch (...) {
        run_exception = std::current_exception();
    }

    grpc_context_work_.reset();
    grpc_context_->stop();
    grpc_context_thread.join();

    if (run_exception) {
        std::rethrow_exception(run_exception);
    }
    SILK_DEBUG << "ClientContext execution loop end [" << std::this_thread::get_id() << "]";
}

ClientContextPool::~ClientContextPool() {
    stop();  // must be called to simplify exposed API, no problem because idempotent
    join();  // must be called to simplify exposed API, no problem because idempotent

    // Ensure *all* agrpc::GrpcContext get destroyed BEFORE any boost::asio::io_context is destroyed to avoid triggering
    // undefined behavior when dispatching calls from i-th agrpc::GrpcContext to j-th boost::asio::io_context w/ i != j
    for (auto& context : contexts_) {
        context.destroy_grpc_context();
    }
}

void ClientContextPool::start() {
    // Cannot restart because ::grpc::CompletionQueue inside agrpc::GrpcContext cannot be reused
    if (stopped_) {
        throw std::logic_error("cannot restart context pool, create another one");
    }

    ContextPool<ClientContext>::start();
}

agrpc::GrpcContext& ClientContextPool::any_grpc_context() {
    return *next_context().grpc_context();
}

}  // namespace silkworm::rpc
