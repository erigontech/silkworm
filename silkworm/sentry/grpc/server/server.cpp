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

#include "server.hpp"

#include <utility>

#include <silkworm/infra/concurrency/task.hpp>

#include <agrpc/grpc_context.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/infra/grpc/server/server.hpp>
#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>

#include "server_calls.hpp"

namespace silkworm::sentry::grpc::server {

using namespace silkworm::log;
using AsyncService = ::sentry::Sentry::AsyncService;
using api::router::ServiceRouter;

class ServerImpl final : public silkworm::rpc::Server {
  public:
    explicit ServerImpl(
        const silkworm::rpc::ServerSettings& config,
        ServiceRouter router);

    ServerImpl(const ServerImpl&) = delete;
    ServerImpl& operator=(const ServerImpl&) = delete;

  private:
    void register_async_services(::grpc::ServerBuilder& builder) override;
    void register_request_calls() override;
    void register_request_calls(agrpc::GrpcContext* grpc_context);

    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    template <class RequestHandler, typename RPC>
    void request_repeatedly(
        RPC rpc,
        agrpc::GrpcContext* grpc_context) {
        auto async_service = &async_service_;
        const auto& router = router_;
        silkworm::rpc::request_repeatedly(*grpc_context, async_service, rpc, [router](auto&&... args) -> Task<void> {
            co_await RequestHandler{std::forward<decltype(args)>(args)...}(router);
        });
    }

    ServiceRouter router_;
    AsyncService async_service_;
};

ServerImpl::ServerImpl(
    const silkworm::rpc::ServerSettings& config,
    ServiceRouter router)
    : silkworm::rpc::Server(config),
      router_(std::move(router)) {
    log::Info("sentry") << "rpc::Server created"
                        << " to listen on: " << config.address_uri << ";"
                        << " contexts: " << config.context_pool_settings.num_contexts;
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
    request_repeatedly<SetStatusCall>(&AsyncService::RequestSetStatus, grpc_context);
    request_repeatedly<HandshakeCall>(&AsyncService::RequestHandShake, grpc_context);
    request_repeatedly<NodeInfoCall>(&AsyncService::RequestNodeInfo, grpc_context);

    request_repeatedly<SendMessageByIdCall>(&AsyncService::RequestSendMessageById, grpc_context);
    request_repeatedly<SendMessageToRandomPeersCall>(&AsyncService::RequestSendMessageToRandomPeers, grpc_context);
    request_repeatedly<SendMessageToAllCall>(&AsyncService::RequestSendMessageToAll, grpc_context);
    request_repeatedly<SendMessageByMinBlockCall>(&AsyncService::RequestSendMessageByMinBlock, grpc_context);
    request_repeatedly<PeerMinBlockCall>(&AsyncService::RequestPeerMinBlock, grpc_context);
    request_repeatedly<MessagesCall>(&AsyncService::RequestMessages, grpc_context);

    request_repeatedly<PeersCall>(&AsyncService::RequestPeers, grpc_context);
    request_repeatedly<PeerCountCall>(&AsyncService::RequestPeerCount, grpc_context);
    request_repeatedly<PeerByIdCall>(&AsyncService::RequestPeerById, grpc_context);
    request_repeatedly<PenalizePeerCall>(&AsyncService::RequestPenalizePeer, grpc_context);
    request_repeatedly<PeerEventsCall>(&AsyncService::RequestPeerEvents, grpc_context);
}

Server::Server(
    const silkworm::rpc::ServerSettings& config,
    ServiceRouter router)
    : p_impl_(std::make_unique<ServerImpl>(config, std::move(router))) {}

Server::~Server() {
    log::Trace("sentry") << "silkworm::sentry::grpc::server::Server::~Server";
}

Task<void> Server::async_run() {
    return p_impl_->async_run("sentry-gsrv");
}

}  // namespace silkworm::sentry::grpc::server
