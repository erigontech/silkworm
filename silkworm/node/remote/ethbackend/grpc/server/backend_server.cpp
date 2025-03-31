// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "backend_server.hpp"

#include <silkworm/infra/concurrency/task.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/node/remote/ethbackend/grpc/server/backend_calls.hpp>

namespace silkworm::ethbackend::grpc::server {

using rpc::request_repeatedly;

BackEndServer::BackEndServer(const rpc::ServerSettings& settings, const EthereumBackEnd& backend)
    : Server(settings), backend_(backend) {
    setup_backend_calls(backend);
    SILK_INFO << "BackEndServer created listening on: " << settings.address_uri;
}

// Register the gRPC services: they must exist for the lifetime of the server built by builder.
void BackEndServer::register_async_services(::grpc::ServerBuilder& builder) {
    builder.RegisterService(&backend_async_service_);
}

void BackEndServer::setup_backend_calls(const EthereumBackEnd& backend) {
    EtherbaseCall::fill_predefined_reply(backend);
    NetVersionCall::fill_predefined_reply(backend);
    BackEndVersionCall::fill_predefined_reply();
    ProtocolVersionCall::fill_predefined_reply();
    ClientVersionCall::fill_predefined_reply(backend);
}

void BackEndServer::register_backend_request_calls(agrpc::GrpcContext* grpc_context) {
    SILK_TRACE << "BackEndService::register_backend_request_calls START";
    auto service = &backend_async_service_;
    auto& backend = backend_;

    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestEtherbase,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await EtherbaseCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestNetVersion,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await NetVersionCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestNetPeerCount,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await NetPeerCountCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestVersion,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await BackEndVersionCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestProtocolVersion,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await ProtocolVersionCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestClientVersion,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await ClientVersionCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestSubscribe,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await SubscribeCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    request_repeatedly(*grpc_context, service, &remote::ETHBACKEND::AsyncService::RequestNodeInfo,
                       [&backend](auto&&... args) -> Task<void> {
                           co_await NodeInfoCall{std::forward<decltype(args)>(args)...}(backend);
                       });
    SILK_TRACE << "BackEndService::register_backend_request_calls END";
}

//! Start server-side RPC requests as required by gRPC async model: one RPC per type is requested in advance.
void BackEndServer::register_request_calls() {
    // Start all server-side RPC requests for each available server context
    for (size_t i = 0; i < num_contexts(); ++i) {
        const auto& context = next_context();
        auto grpc_context = context.server_grpc_context();

        // Register initial requested calls for ETHBACKEND and KV services
        register_backend_request_calls(grpc_context);
    }
}

}  // namespace silkworm::ethbackend::grpc::server
