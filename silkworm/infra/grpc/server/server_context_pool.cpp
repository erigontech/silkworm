// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "server_context_pool.hpp"

#include <exception>
#include <thread>

#include <silkworm/infra/common/log.hpp>

namespace silkworm::rpc {

using namespace concurrency;

static std::string build_thread_name(const char name_tag[11], size_t id) {
    return {name_tag + std::to_string(id)};
}

ServerContext::ServerContext(size_t context_id, ServerCompletionQueuePtr queue)
    : Context{context_id},
      server_grpc_context_{std::make_unique<agrpc::GrpcContext>(std::move(queue))},
      client_grpc_context_{std::make_unique<agrpc::GrpcContext>()},
      server_grpc_context_work_{boost::asio::make_work_guard(server_grpc_context_->get_executor())},
      client_grpc_context_work_{boost::asio::make_work_guard(client_grpc_context_->get_executor())} {}

void ServerContext::execute_loop() {
    SILK_TRACE << "ServerContext execution loop start [" << std::this_thread::get_id() << "]";

    std::thread server_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_s", id()).c_str());
        SILK_TRACE << "Server GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        server_grpc_context_->run();
        SILK_TRACE << "Server GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};

    std::thread client_grpc_context_thread{[&]() {
        log::set_thread_name(build_thread_name("grpc_ctx_c", id()).c_str());
        SILK_TRACE << "Client GrpcContext execution loop start [" << std::this_thread::get_id() << "]";
        client_grpc_context_->run_completion_queue();
        SILK_TRACE << "Client GrpcContext execution loop end [" << std::this_thread::get_id() << "]";
    }};

    std::exception_ptr run_exception;
    try {
        ioc()->run();
    } catch (...) {
        run_exception = std::current_exception();
    }

    server_grpc_context_work_.reset();
    client_grpc_context_work_.reset();
    server_grpc_context_->stop();
    client_grpc_context_->stop();
    server_grpc_context_thread.join();
    client_grpc_context_thread.join();

    if (run_exception) {
        std::rethrow_exception(run_exception);
    }
    SILK_TRACE << "ServerContext execution loop end [" << std::this_thread::get_id() << "]";
}

ServerContextPool::ServerContextPool(
    concurrency::ContextPoolSettings settings,
    grpc::ServerBuilder& server_builder) {
    if (settings.num_contexts == 0) {
        throw std::logic_error("ServerContextPool size is 0");
    }

    for (size_t i{0}; i < settings.num_contexts; ++i) {
        add_context(ServerContext{i, server_builder.AddCompletionQueue()});
    }
}

}  // namespace silkworm::rpc
