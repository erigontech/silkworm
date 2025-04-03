// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "server.hpp"

#include <utility>

#include <agrpc/grpc_context.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/execution/execution.grpc.pb.h>

#include "server_calls.hpp"

namespace silkworm::execution::grpc::server {

using namespace silkworm::log;
using AsyncService = ::execution::Execution::AsyncService;

class ServerImpl final : public rpc::Server {
  public:
    ServerImpl(rpc::ServerSettings settings, std::shared_ptr<api::DirectService> service);

    ServerImpl(const ServerImpl&) = delete;
    ServerImpl& operator=(const ServerImpl&) = delete;

  private:
    void register_async_services(::grpc::ServerBuilder& builder) override;
    void register_request_calls() override;
    void register_request_calls(agrpc::GrpcContext* grpc_context);

    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    template <class RequestHandler, typename RPC>
    void request_repeatedly(RPC rpc, agrpc::GrpcContext* grpc_context) {
        auto async_service = &async_service_;
        auto& service = service_;
        // Registering repeatedly in asio-grpc will guarantee the RequestHandler lambda lifetime
        rpc::request_repeatedly(*grpc_context, async_service, rpc, [&service](auto&&... args) -> Task<void> {
            co_await RequestHandler{std::forward<decltype(args)>(args)...}(*service);
        });
    }

    std::shared_ptr<api::DirectService> service_;
    AsyncService async_service_;
};

ServerImpl::ServerImpl(rpc::ServerSettings settings, std::shared_ptr<api::DirectService> service)
    : rpc::Server(std::move(settings)), service_{std::move(service)} {
    SILK_INFO_M("execution")
        << "rpc::Server created listening on: "
        << this->settings().address_uri
        << " contexts: " << this->settings().context_pool_settings.num_contexts;
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void ServerImpl::register_async_services(::grpc::ServerBuilder& builder) {
    builder.RegisterService(&async_service_);
}

//! Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void ServerImpl::register_request_calls() {
    for (size_t i = 0; i < num_contexts(); ++i) {
        const auto& context = next_context();
        register_request_calls(context.server_grpc_context());
    }
}

void ServerImpl::register_request_calls(agrpc::GrpcContext* grpc_context) {
    request_repeatedly<InsertBlocksCall>(&AsyncService::RequestInsertBlocks, grpc_context);

    request_repeatedly<ValidateChainCall>(&AsyncService::RequestValidateChain, grpc_context);
    request_repeatedly<UpdateForkChoiceCall>(&AsyncService::RequestUpdateForkChoice, grpc_context);

    request_repeatedly<AssembleBlockCall>(&AsyncService::RequestAssembleBlock, grpc_context);
    request_repeatedly<GetAssembledBlockCall>(&AsyncService::RequestGetAssembledBlock, grpc_context);

    request_repeatedly<CurrentHeaderCall>(&AsyncService::RequestCurrentHeader, grpc_context);
    request_repeatedly<GetTDCall>(&AsyncService::RequestGetTD, grpc_context);
    request_repeatedly<GetHeaderCall>(&AsyncService::RequestGetHeader, grpc_context);
    request_repeatedly<GetBodyCall>(&AsyncService::RequestGetBody, grpc_context);
    request_repeatedly<HasBlockCall>(&AsyncService::RequestHasBlock, grpc_context);

    request_repeatedly<GetBodiesByRangeCall>(&AsyncService::RequestGetBodiesByRange, grpc_context);
    request_repeatedly<GetBodiesByHashesCall>(&AsyncService::RequestGetBodiesByHashes, grpc_context);

    request_repeatedly<IsCanonicalHashCall>(&AsyncService::RequestIsCanonicalHash, grpc_context);
    request_repeatedly<GetHeaderHashNumberCall>(&AsyncService::RequestGetHeaderHashNumber, grpc_context);
    request_repeatedly<GetForkChoiceCall>(&AsyncService::RequestGetForkChoice, grpc_context);

    request_repeatedly<ReadyCall>(&AsyncService::RequestReady, grpc_context);
    request_repeatedly<FrozenBlocksCall>(&AsyncService::RequestFrozenBlocks, grpc_context);
}

Server::Server(rpc::ServerSettings settings, std::shared_ptr<api::DirectService> service)
    : p_impl_(std::make_unique<ServerImpl>(std::move(settings), std::move(service))) {}

Server::~Server() {
    SILK_TRACE_M("execution") << "silkworm::execution::grpc::server::Server::~Server";
}

Task<void> Server::async_run(std::optional<size_t> stack_size) {
    return p_impl_->async_run("exec-engine", stack_size);
}

}  // namespace silkworm::execution::grpc::server
