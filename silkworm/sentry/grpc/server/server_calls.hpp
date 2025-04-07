// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include <memory>
#include <sstream>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/this_coro.hpp>
#include <grpcpp/grpcpp.h>
#include <gsl/util>

#include <silkworm/core/common/base.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/grpc/server/call.hpp>
#include <silkworm/sentry/api/common/message_id_set.hpp>
#include <silkworm/sentry/api/common/node_info.hpp>
#include <silkworm/sentry/api/common/peer_event.hpp>
#include <silkworm/sentry/api/common/peer_info.hpp>
#include <silkworm/sentry/api/router/messages_call.hpp>
#include <silkworm/sentry/api/router/peer_call.hpp>
#include <silkworm/sentry/api/router/peer_events_call.hpp>
#include <silkworm/sentry/api/router/send_message_call.hpp>
#include <silkworm/sentry/api/router/service_router.hpp>
#include <silkworm/sentry/eth/fork_id.hpp>

#include "../interfaces/eth_version.hpp"
#include "../interfaces/message.hpp"
#include "../interfaces/node_info.hpp"
#include "../interfaces/peer_event.hpp"
#include "../interfaces/peer_id.hpp"
#include "../interfaces/peer_info.hpp"
#include "../interfaces/sent_peer_ids.hpp"
#include "../interfaces/status_data.hpp"

namespace silkworm::sentry::grpc::server {

namespace protobuf = google::protobuf;
namespace proto = ::sentry;
namespace proto_types = ::types;
using AsyncService = proto::Sentry::AsyncService;
namespace sw_rpc = silkworm::rpc;
using api::router::ServiceRouter;

// rpc SetStatus(StatusData) returns (SetStatusReply);
class SetStatusCall : public sw_rpc::server::UnaryCall<proto::StatusData, proto::SetStatusReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto status = interfaces::status_data_from_proto(request_, router.eth_version);
        co_await router.status_channel.send(status);
        co_await agrpc::finish(responder_, proto::SetStatusReply{}, ::grpc::Status::OK);
    }
};

// HandShake - pre-requirement for all Send* methods - returns ETH protocol version,
// without knowledge of protocol - impossible encode correct P2P message
// rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
class HandshakeCall : public sw_rpc::server::UnaryCall<protobuf::Empty, proto::HandShakeReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        proto::HandShakeReply reply;
        auto protocol = interfaces::protocol_from_eth_version(router.eth_version);
        reply.set_protocol(protocol);
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// NodeInfo returns a collection of metadata known about the host.
// rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
class NodeInfoCall : public sw_rpc::server::UnaryCall<protobuf::Empty, proto_types::NodeInfoReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto reply = interfaces::proto_node_info_from_node_info(router.node_info_provider());
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

inline Task<proto::SentPeers> do_send_message_call(
    const ServiceRouter& router,
    const proto::OutboundMessageData& request,
    api::PeerFilter peer_filter) {
    auto message = interfaces::message_from_outbound_data(request);

    auto executor = co_await boost::asio::this_coro::executor;
    api::router::SendMessageCall call{std::move(message), peer_filter, executor};

    co_await router.send_message_channel.send(call);

    auto sent_peer_keys = co_await call.result();

    proto::SentPeers reply = interfaces::sent_peers_ids_from_peer_keys(sent_peer_keys);
    co_return reply;
}

// rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
class SendMessageByIdCall : public sw_rpc::server::UnaryCall<proto::SendMessageByIdRequest, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto peer_public_key = interfaces::peer_public_key_from_id(request_.peer_id());
        proto::SentPeers reply = co_await do_send_message_call(
            router,
            request_.data(),
            api::PeerFilter::with_peer_public_key(peer_public_key));
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
class SendMessageToRandomPeersCall : public sw_rpc::server::UnaryCall<proto::SendMessageToRandomPeersRequest, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        proto::SentPeers reply = co_await do_send_message_call(
            router,
            request_.data(),
            api::PeerFilter::with_max_peers(request_.max_peers()));
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
class SendMessageToAllCall : public sw_rpc::server::UnaryCall<proto::OutboundMessageData, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        proto::SentPeers reply = co_await do_send_message_call(router, request_, api::PeerFilter{});
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
class SendMessageByMinBlockCall : public sw_rpc::server::UnaryCall<proto::SendMessageByMinBlockRequest, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        // TODO: use request_.min_block()
        proto::SentPeers reply = co_await do_send_message_call(
            router,
            request_.data(),
            api::PeerFilter::with_max_peers(request_.max_peers()));
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
class PeerMinBlockCall : public sw_rpc::server::UnaryCall<proto::PeerMinBlockRequest, protobuf::Empty> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& /*router*/) {
        // TODO: implement
        co_await agrpc::finish(responder_, protobuf::Empty{}, ::grpc::Status::OK);
    }
};

// Subscribe to receive messages.
// Calling multiple times with a different set of ids starts separate streams.
// It is possible to subscribe to the same set if ids more than once.
// rpc Messages(MessagesRequest) returns (stream InboundMessage);
class MessagesCall : public sw_rpc::server::ServerStreamingCall<proto::MessagesRequest, proto::InboundMessage> {
  public:
    using Base::ServerStreamingCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto executor = co_await boost::asio::this_coro::executor;
        api::router::MessagesCall call{
            interfaces::message_id_set_from_messages_request(request_),
            executor,
        };

        auto unsubscribe_signal = call.unsubscribe_signal();
        [[maybe_unused]] auto _ = gsl::finally([=]() { unsubscribe_signal->notify(); });

        co_await router.message_calls_channel.send(call);
        auto messages_channel = co_await call.result();

        bool write_ok = true;
        while (write_ok) {
            auto message = co_await messages_channel->receive();

            proto::InboundMessage reply = interfaces::inbound_message_from_message(message.message);
            if (message.peer_public_key) {
                reply.mutable_peer_id()->CopyFrom(interfaces::peer_id_from_public_key(message.peer_public_key.value()));
            }

            write_ok = co_await agrpc::write(responder_, reply);
        }

        co_await agrpc::finish(responder_, ::grpc::Status::OK);
    }
};

// rpc Peers(google.protobuf.Empty) returns (PeersReply);
class PeersCall : public sw_rpc::server::UnaryCall<protobuf::Empty, proto::PeersReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto executor = co_await boost::asio::this_coro::executor;
        auto call = std::make_shared<concurrency::AwaitablePromise<api::PeerInfos>>(executor);
        auto call_future = call->get_future();

        co_await router.peers_calls_channel.send(call);
        auto peers = co_await call_future.get_async();

        proto::PeersReply reply = interfaces::proto_peers_reply_from_peer_infos(peers);

        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
class PeerCountCall : public sw_rpc::server::UnaryCall<proto::PeerCountRequest, proto::PeerCountReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto executor = co_await boost::asio::this_coro::executor;
        auto call = std::make_shared<concurrency::AwaitablePromise<size_t>>(executor);
        auto call_future = call->get_future();

        co_await router.peer_count_calls_channel.send(call);
        auto count = co_await call_future.get_async();

        proto::PeerCountReply reply;
        reply.set_count(count);
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
class PeerByIdCall : public sw_rpc::server::UnaryCall<proto::PeerByIdRequest, proto::PeerByIdReply> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto peer_public_key = interfaces::peer_public_key_from_id(request_.peer_id());
        auto executor = co_await boost::asio::this_coro::executor;
        api::router::PeerCall call{peer_public_key, executor};
        auto call_future = call.result_promise->get_future();

        co_await router.peer_calls_channel.send(call);
        auto peer_opt = co_await call_future.get_async();

        proto::PeerByIdReply reply = interfaces::proto_peer_reply_from_peer_info_opt(peer_opt);
        co_await agrpc::finish(responder_, reply, ::grpc::Status::OK);
    }
};

// rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
class PenalizePeerCall : public sw_rpc::server::UnaryCall<proto::PenalizePeerRequest, protobuf::Empty> {
  public:
    using Base::UnaryCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto peer_public_key = interfaces::peer_public_key_from_id(request_.peer_id());

        co_await router.peer_penalize_calls_channel.send({peer_public_key});

        co_await agrpc::finish(responder_, protobuf::Empty{}, ::grpc::Status::OK);
    }
};

// Subscribe to notifications about connected or lost peers.
// rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
class PeerEventsCall : public sw_rpc::server::ServerStreamingCall<proto::PeerEventsRequest, proto::PeerEvent> {
  public:
    using Base::ServerStreamingCall;

    Task<void> operator()(const ServiceRouter& router) {
        auto executor = co_await boost::asio::this_coro::executor;
        api::router::PeerEventsCall call{executor};
        auto call_future = call.result_promise->get_future();

        auto unsubscribe_signal = call.unsubscribe_signal;
        [[maybe_unused]] auto _ = gsl::finally([=]() { unsubscribe_signal->notify(); });

        co_await router.peer_events_calls_channel.send(call);
        auto events_channel = co_await call_future.get_async();

        bool write_ok = true;
        while (write_ok) {
            auto event = co_await events_channel->receive();
            proto::PeerEvent reply = interfaces::proto_peer_event_from_peer_event(event);
            write_ok = co_await agrpc::write(responder_, reply);
        }

        co_await agrpc::finish(responder_, ::grpc::Status::OK);
    }
};

}  // namespace silkworm::sentry::grpc::server
