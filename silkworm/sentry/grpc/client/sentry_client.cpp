// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "sentry_client.hpp"

#include <functional>
#include <stdexcept>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/this_coro.hpp>
#include <grpcpp/grpcpp.h>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/client/reconnect.hpp>
#include <silkworm/interfaces/p2psentry/sentry.grpc.pb.h>
#include <silkworm/sentry/api/common/service.hpp>

#include "../interfaces/eth_version.hpp"
#include "../interfaces/message.hpp"
#include "../interfaces/node_info.hpp"
#include "../interfaces/peer_event.hpp"
#include "../interfaces/peer_id.hpp"
#include "../interfaces/peer_info.hpp"
#include "../interfaces/sent_peer_ids.hpp"
#include "../interfaces/status_data.hpp"

namespace silkworm::sentry::grpc::client {

namespace proto = ::sentry;
using Stub = proto::Sentry::StubInterface;
namespace sw_rpc = silkworm::rpc;
using namespace api;

static std::shared_ptr<::grpc::Channel> make_grpc_channel(const std::string& address_uri) {
    return ::grpc::CreateChannel(address_uri, ::grpc::InsecureChannelCredentials());
}

class SentryClientImpl final : public api::Service {
  public:
    explicit SentryClientImpl(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
        : channel_(make_grpc_channel(address_uri)),
          stub_(proto::Sentry::NewStub(channel_)),
          grpc_context_(grpc_context),
          on_disconnect_([]() -> Task<void> { co_return; }) {}

    ~SentryClientImpl() override = default;

    SentryClientImpl(const SentryClientImpl&) = delete;
    SentryClientImpl& operator=(const SentryClientImpl&) = delete;

    bool is_ready() {
        auto state = channel_->GetState(false);
        return (state == GRPC_CHANNEL_READY) || (state == GRPC_CHANNEL_IDLE);
    }

    void on_disconnect(std::function<Task<void>()> callback) {
        on_disconnect_ = std::move(callback);
    }

    Task<void> reconnect() {
        co_await sw_rpc::reconnect_channel(*channel_, "sentry");
    }

    // rpc SetStatus(StatusData) returns (SetStatusReply);
    Task<void> set_status(eth::StatusData status_data) override {
        proto::StatusData request = interfaces::proto_status_data_from_status_data(status_data);
        co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncSetStatus, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
    }

    // rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
    Task<uint8_t> handshake() override {
        google::protobuf::Empty request;
        proto::HandShakeReply reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncHandShake, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        uint8_t result = interfaces::eth_version_from_protocol(reply.protocol());
        co_return result;
    }

    // rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
    Task<NodeInfos> node_infos() override {
        google::protobuf::Empty request;
        types::NodeInfoReply reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncNodeInfo, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::node_info_from_proto_node_info(reply);
        co_return NodeInfos{result};
    }

    // rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
    Task<PeerKeys> send_message_by_id(Message message, EccPublicKey public_key) override {
        proto::SendMessageByIdRequest request;
        request.mutable_data()->CopyFrom(interfaces::outbound_data_from_message(message));
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));

        proto::SentPeers reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncSendMessageById, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
    Task<PeerKeys> send_message_to_random_peers(Message message, size_t max_peers) override {
        proto::SendMessageToRandomPeersRequest request;
        request.mutable_data()->CopyFrom(interfaces::outbound_data_from_message(message));
        request.set_max_peers(max_peers);

        proto::SentPeers reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncSendMessageToRandomPeers, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
    Task<PeerKeys> send_message_to_all(Message message) override {
        proto::OutboundMessageData request = interfaces::outbound_data_from_message(message);
        proto::SentPeers reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncSendMessageToAll, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
    Task<PeerKeys> send_message_by_min_block(Message message, size_t max_peers) override {
        proto::SendMessageByMinBlockRequest request;
        request.mutable_data()->CopyFrom(interfaces::outbound_data_from_message(message));
        // TODO: set_min_block
        // request.set_min_block()
        request.set_max_peers(max_peers);

        proto::SentPeers reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncSendMessageByMinBlock, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::peer_keys_from_sent_peers_ids(reply);
        co_return result;
    }

    // rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
    Task<void> peer_min_block(EccPublicKey public_key) override {
        proto::PeerMinBlockRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        // TODO: set_min_block
        // request.set_min_block()
        co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncPeerMinBlock, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
    }

    // rpc Messages(MessagesRequest) returns (stream InboundMessage);
    Task<void> messages(
        MessageIdSet message_id_filter,
        std::function<Task<void>(MessageFromPeer)> consumer) override {
        proto::MessagesRequest request = interfaces::messages_request_from_message_id_set(message_id_filter);

        std::function<Task<void>(proto::InboundMessage)> proto_consumer =
            [consumer = std::move(consumer)](proto::InboundMessage message) -> Task<void> {
            MessageFromPeer message_from_peer{
                interfaces::message_from_inbound_message(message),
                {interfaces::peer_public_key_from_id(message.peer_id())},
            };
            co_await consumer(std::move(message_from_peer));
        };

        co_await sw_rpc::server_streaming_rpc_with_retries(
            &Stub::PrepareAsyncMessages,
            stub_,
            std::move(request),
            grpc_context_,
            on_disconnect_,
            *channel_,
            "sentry",
            std::move(proto_consumer));
    }

    // rpc Peers(google.protobuf.Empty) returns (PeersReply);
    Task<PeerInfos> peers() override {
        google::protobuf::Empty request;
        proto::PeersReply reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncPeers, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::peer_infos_from_proto_peers_reply(reply);
        co_return result;
    }

    // rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
    Task<size_t> peer_count() override {
        proto::PeerCountRequest request;
        proto::PeerCountReply reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncPeerCount, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = static_cast<size_t>(reply.count());
        co_return result;
    }

    // rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
    Task<std::optional<PeerInfo>> peer_by_id(EccPublicKey public_key) override {
        proto::PeerByIdRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        proto::PeerByIdReply reply = co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncPeerById, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
        auto result = interfaces::peer_info_opt_from_proto_peer_reply(reply);
        co_return result;
    }

    // rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
    Task<void> penalize_peer(EccPublicKey public_key) override {
        proto::PenalizePeerRequest request;
        request.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(public_key));
        request.set_penalty(proto::PenaltyKind::Kick);
        co_await sw_rpc::unary_rpc_with_retries(&Stub::AsyncPenalizePeer, *stub_, std::move(request), grpc_context_, on_disconnect_, *channel_, "sentry");
    }

    // rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
    Task<void> peer_events(
        std::function<Task<void>(PeerEvent)> consumer) override {
        proto::PeerEventsRequest request;

        std::function<Task<void>(proto::PeerEvent)> proto_consumer =
            [consumer = std::move(consumer)](proto::PeerEvent event) -> Task<void> {
            co_await consumer(interfaces::peer_event_from_proto_peer_event(event));
        };

        co_await sw_rpc::server_streaming_rpc_with_retries(
            &Stub::PrepareAsyncPeerEvents,
            stub_,
            std::move(request),
            grpc_context_,
            on_disconnect_,
            *channel_,
            "sentry",
            std::move(proto_consumer));
    }

  private:
    std::shared_ptr<::grpc::Channel> channel_;
    std::unique_ptr<Stub> stub_;
    agrpc::GrpcContext& grpc_context_;
    std::function<Task<void>()> on_disconnect_;
};

SentryClient::SentryClient(const std::string& address_uri, agrpc::GrpcContext& grpc_context)
    : p_impl_(std::make_shared<SentryClientImpl>(address_uri, grpc_context)) {}

SentryClient::~SentryClient() {
    SILK_TRACE_M("sentry") << "silkworm::sentry::grpc::client::SentryClient::~SentryClient";
}

Task<std::shared_ptr<api::Service>> SentryClient::service() {
    co_return p_impl_;
}

bool SentryClient::is_ready() {
    return p_impl_->is_ready();
}

void SentryClient::on_disconnect(std::function<Task<void>()> callback) {
    p_impl_->on_disconnect(std::move(callback));
}

Task<void> SentryClient::reconnect() {
    return p_impl_->reconnect();
}

}  // namespace silkworm::sentry::grpc::client
