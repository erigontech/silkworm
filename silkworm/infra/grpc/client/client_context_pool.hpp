// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <cstddef>
#include <functional>
#include <memory>

#include <agrpc/asio_grpc.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/concurrency/context_pool.hpp>
#include <silkworm/infra/concurrency/context_pool_settings.hpp>
#include <silkworm/infra/grpc/common/grpc_context_pool.hpp>

namespace silkworm::rpc {

using ChannelFactory = std::function<std::shared_ptr<::grpc::Channel>()>;

//! Asynchronous client scheduler running an execution loop w/ integrated gRPC client.
class ClientContext : public concurrency::Context {
  public:
    explicit ClientContext(size_t context_id);

    agrpc::GrpcContext* grpc_context() const noexcept { return grpc_context_.get(); }

    //! Execute the scheduler loop until stopped.
    void execute_loop() override;

  private:
    void destroy_grpc_context();

    //! The asio-grpc asynchronous event scheduler.
    std::shared_ptr<agrpc::GrpcContext> grpc_context_;

    //! The work-tracking executor that keep the asio-grpc scheduler running.
    boost::asio::executor_work_guard<agrpc::GrpcContext::executor_type> grpc_context_work_;

    friend class ClientContextPool;
};

//! Pool of \ref ClientContext instances running as separate reactive schedulers.
//! \warning currently cannot start/stop more than once because ::grpc::CompletionQueue cannot be used after shutdown
class ClientContextPool : public concurrency::ContextPool<ClientContext>, public GrpcContextPool {
  public:
    using concurrency::ContextPool<ClientContext>::ContextPool;
    ~ClientContextPool() override;

    ClientContextPool(const ClientContextPool&) = delete;
    ClientContextPool& operator=(const ClientContextPool&) = delete;

    void start() override;

    agrpc::GrpcContext& any_grpc_context() override;
};

}  // namespace silkworm::rpc
