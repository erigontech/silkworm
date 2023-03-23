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

#include "sentry_client.hpp"

#include <functional>
#include <stdexcept>

#include <silkworm/node/concurrency/coroutine.hpp>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/this_coro.hpp>
#include <grpcpp/grpcpp.h>
#include <p2psentry/sentry.grpc.pb.h>

#include <silkworm/node/common/log.hpp>
#include <silkworm/node/rpc/client/call.hpp>

#include "../interfaces/eth_version.hpp"
#include "../interfaces/message.hpp"
#include "../interfaces/node_info.hpp"
#include "../interfaces/peer_event.hpp"
#include "../interfaces/peer_id.hpp"
#include "../interfaces/peer_info.hpp"
#include "../interfaces/sent_peer_ids.hpp"
#include "../interfaces/status_data.hpp"

namespace silkworm::sentry::rpc::client {

using boost::asio::awaitable;
namespace proto = ::sentry;
using Stub = proto::Sentry::Stub;
namespace sw_rpc = silkworm::rpc;
using namespace api::api_common;

static std::shared_ptr<grpc::Channel> make_grpc_channel(const std::string& address_uri) {
    return grpc::CreateChannel(address_uri, grpc::InsecureChannelCredentials());
}

class SentryClientImpl final : public api::api_common::Service {
  public:
    explicit SentryClientImpl(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
        : stub_(proto::Sentry::NewStub(make_grpc_channel(address_uri))),
          grpc_context_(grpc_context) {}

    ~SentryClientImpl() override = default;

    SentryClientImpl(const SentryClientImpl&) = delete;
    SentryClientImpl& operator=(const SentryClientImpl&) = delete;

  private:
    // rpc SetStatus(StatusData) returns (SetStatusReply);
    awaitable<void> set_status(eth::StatusData status_data) override {
        proto::StatusData request = interfaces::proto_status_data_from_status_data(status_data);
        co_await sw_rpc::unary_rpc(&Stub::AsyncSetStatus, stub_, std::move(request), grpc_context_);
    }

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    awaitable<uint8_t> handshake() override {
        google::protobuf::Empty request;
        proto::HandShakeReply reply = co_await sw_rpc::unary_rpc(&Stub::AsyncHandShake, stub_, std::move(request), grpc_context_);
        uint8_t result = interfaces::eth_version_from_protocol(reply.protocol());
        co_return result;
    }

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    awaitable<NodeInfo> node_info() override {
        google::protobuf::Empty request;
        types::NodeInfoReply reply = co_await sw_rpc::unary_rpc(&Stub::AsyncNodeInfo, stub_, std::move(request), grpc_context_);
        auto result = interfaces::node_info_from_proto_node_info(reply);
        co_return result;
    }

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_by_id(common::Message message, common::EccPublicKey public_key) override {
        proto::SendMessageByIdRequest request;
        request.mutable_data()->CopyFrom(interfaces::outbound_data_from_message(message));
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));

        proto::SentPeers reply = co_await sw_rpc::unary_rpc(&Stub::AsyncSendMessageById, stub_, std::move(request), grpc_context_);
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_to_random_peers(common::Message message, size_t max_peers) override {
        proto::SendMessageToRandomPeersRequest request;
        request.mutable_data()->CopyFrom(interfaces::outbound_data_from_message(message));
        request.set_max_peers(max_peers);

        proto::SentPeers reply = co_await sw_rpc::unary_rpc(&Stub::AsyncSendMessageToRandomPeers, stub_, std::move(request), grpc_context_);
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    awaitable<PeerKeys> send_message_to_all(common::Message message) override {
        proto::OutboundMessageData request = interfaces::outbound_data_from_message(message);
        proto::SentPeers reply = co_await sw_rpc::unary_rpc(&Stub::AsyncSendMessageToAll, stub_, std::move(request), grpc_context_);
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    awaitable<PeerKeys> send_message_by_min_block(common::Message message, size_t max_peers) override {
        proto::SendMessageByMinBlockRequest request;
        request.mutable_data()->CopyFrom(interfaces::outbound_data_from_message(message));
        // TODO: set_min_block
        // request.set_min_block()
        request.set_max_peers(max_peers);

        proto::SentPeers reply = co_await sw_rpc::unary_rpc(&Stub::AsyncSendMessageByMinBlock, stub_, std::move(request), grpc_context_);
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    awaitable<void> peer_min_block(common::EccPublicKey public_key) override {
        proto::PeerMinBlockRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        // TODO: set_min_block
        // request.set_min_block()
        co_await sw_rpc::unary_rpc(&Stub::AsyncPeerMinBlock, stub_, std::move(request), grpc_context_);
    }

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    awaitable<void> messages(
        MessageIdSet message_id_filter,
        std::function<awaitable<void>(MessageFromPeer)> consumer) override {
        proto::MessagesRequest request = interfaces::messages_request_from_message_id_set(message_id_filter);

        std::function<awaitable<void>(proto::InboundMessage)> proto_consumer =
            [consumer = std::move(consumer)](proto::InboundMessage message) -> awaitable<void> {
            MessageFromPeer message_from_peer{
                interfaces::message_from_inbound_message(message),
                {interfaces::peer_public_key_from_id(message.peer_id())},
            };
            co_await consumer(std::move(message_from_peer));
        };

        co_await sw_rpc::streaming_rpc(
            &Stub::PrepareAsyncMessages,
            stub_,
            std::move(request),
            grpc_context_,
            std::move(proto_consumer));
    }

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    awaitable<PeerInfos> peers() override {
        google::protobuf::Empty request;
        proto::PeersReply reply = co_await sw_rpc::unary_rpc(&Stub::AsyncPeers, stub_, std::move(request), grpc_context_);
        auto result = interfaces::peer_infos_from_proto_peers_reply(reply);
        co_return result;
    }

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    awaitable<size_t> peer_count() override {
        proto::PeerCountRequest request;
        proto::PeerCountReply reply = co_await sw_rpc::unary_rpc(&Stub::AsyncPeerCount, stub_, std::move(request), grpc_context_);
        auto result = static_cast<size_t>(reply.count());
        co_return result;
    }

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    awaitable<std::optional<PeerInfo>> peer_by_id(common::EccPublicKey public_key) override {
        proto::PeerByIdRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        proto::PeerByIdReply reply = co_await sw_rpc::unary_rpc(&Stub::AsyncPeerById, stub_, std::move(request), grpc_context_);
        auto result = interfaces::peer_info_opt_from_proto_peer_reply(reply);
        co_return result;
    }

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    awaitable<void> penalize_peer(common::EccPublicKey public_key) override {
        proto::PenalizePeerRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        request.set_penalty(proto::PenaltyKind::Kick);
        co_await sw_rpc::unary_rpc(&Stub::AsyncPenalizePeer, stub_, std::move(request), grpc_context_);
    }

    // rpc PeerUseless(PeerUselessRequest) returns (google.protobuf.Empty);
    awaitable<void> peer_useless(common::EccPublicKey public_key) override {
        proto::PeerUselessRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        co_await sw_rpc::unary_rpc(&Stub::AsyncPeerUseless, stub_, std::move(request), grpc_context_);
    }

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    awaitable<void> peer_events(
        std::function<awaitable<void>(PeerEvent)> consumer) override {
        proto::PeerEventsRequest request;

        std::function<awaitable<void>(proto::PeerEvent)> proto_consumer =
            [consumer = std::move(consumer)](proto::PeerEvent event) -> awaitable<void> {
            co_await consumer(interfaces::peer_event_from_proto_peer_event(event));
        };

        co_await sw_rpc::streaming_rpc(
            &Stub::PrepareAsyncPeerEvents,
            stub_,
            std::move(request),
            grpc_context_,
            std::move(proto_consumer));
    }

    std::unique_ptr<Stub> stub_;
    agrpc::GrpcContext& grpc_context_;
};

SentryClient::SentryClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
    : p_impl_(std::make_shared<SentryClientImpl>(address_uri, grpc_context)) {}

SentryClient::~SentryClient() {
    log::Trace() << "silkworm::sentry::rpc::client::SentryClient::~SentryClient";
}

std::shared_ptr<api::api_common::Service> SentryClient::service() {
    return p_impl_;
}

}  // namespace silkworm::sentry::rpc::client
