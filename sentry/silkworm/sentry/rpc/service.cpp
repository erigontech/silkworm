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

#include "service.hpp"

#include <algorithm>
#include <optional>
#include <vector>

#include <boost/asio/awaitable.hpp>

#include <silkworm/common/base.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/downloader/internals/sentry_type_casts.hpp>
#include <silkworm/rpc/server/call.hpp>
#include <silkworm/sentry/eth/fork_id.hpp>

namespace silkworm::sentry::rpc {

using boost::asio::awaitable;
using boost::asio::io_context;
namespace protobuf = google::protobuf;
namespace proto = ::sentry;
namespace proto_types = ::types;
using AsyncService = proto::Sentry::AsyncService;
namespace sw_rpc = silkworm::rpc;

// rpc SetStatus(StatusData) returns (SetStatusReply);
class SetStatusCall : public sw_rpc::server::UnaryCall<proto::StatusData, proto::SetStatusReply> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& state) {
        auto status = make_status_data(request_, state);
        bool ok = state.status_channel.try_send(status);
        if (!ok) {
            log::Error() << "SetStatusCall: status_channel is clogged";
        }
        co_await agrpc::finish(responder_, proto::SetStatusReply{}, grpc::Status::OK);
    }

    static eth::StatusData make_status_data(const proto::StatusData& data, const ServiceState& state) {
        auto& data_forks = data.fork_data().forks();
        std::vector<BlockNum> fork_block_numbers;
        fork_block_numbers.resize(static_cast<size_t>(data_forks.size()));
        std::copy(data_forks.cbegin(), data_forks.cend(), fork_block_numbers.begin());

        Bytes genesis_hash{hash_from_H256(data.fork_data().genesis())};

        auto message = eth::StatusMessage{
            state.eth_version,
            data.network_id(),
            uint256_from_H256(data.total_difficulty()),
            Bytes{hash_from_H256(data.best_hash())},
            genesis_hash,
            eth::ForkId{genesis_hash, fork_block_numbers, data.max_block()},
        };

        return eth::StatusData{
            std::move(fork_block_numbers),
            data.max_block(),
            std::move(message),
        };
    }
};

// HandShake - pre-requirement for all Send* methods - returns ETH protocol version,
// without knowledge of protocol - impossible encode correct P2P message
// rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
class HandshakeCall : public sw_rpc::server::UnaryCall<protobuf::Empty, proto::HandShakeReply> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& state) {
        proto::HandShakeReply reply;
        assert(proto::Protocol_MIN == proto::Protocol::ETH65);
        reply.set_protocol(static_cast<proto::Protocol>(state.eth_version - 65));
        co_await agrpc::finish(responder_, reply, grpc::Status::OK);
    }
};

// NodeInfo returns a collection of metadata known about the host.
// rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
class NodeInfoCall : public sw_rpc::server::UnaryCall<protobuf::Empty, proto_types::NodeInfoReply> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "NodeInfoCall"});
    }
};

// rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
class SendMessageByIdCall : public sw_rpc::server::UnaryCall<proto::SendMessageByIdRequest, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "SendMessageByIdCall"});
    }
};

// rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
class SendMessageToRandomPeersCall : public sw_rpc::server::UnaryCall<proto::SendMessageToRandomPeersRequest, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "SendMessageToRandomPeersCall"});
    }
};

// rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
class SendMessageToAllCall : public sw_rpc::server::UnaryCall<proto::OutboundMessageData, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "SendMessageToAllCall"});
    }
};

// rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
class SendMessageByMinBlockCall : public sw_rpc::server::UnaryCall<proto::SendMessageByMinBlockRequest, proto::SentPeers> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "SendMessageByMinBlockCall"});
    }
};

// rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
class PeerMinBlockCall : public sw_rpc::server::UnaryCall<proto::PeerMinBlockRequest, protobuf::Empty> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "PeerMinBlockCall"});
    }
};

// Subscribe to receive messages.
// Calling multiple times with a different set of ids starts separate streams.
// It is possible to subscribe to the same set if ids more than once.
// rpc Messages(MessagesRequest) returns (stream InboundMessage);
class MessagesCall : public sw_rpc::server::ServerStreamingCall<proto::MessagesRequest, proto::InboundMessage> {
  public:
    using Base::ServerStreamingCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "MessagesCall"});
    }
};

// rpc Peers(google.protobuf.Empty) returns (PeersReply);
class PeersCall : public sw_rpc::server::UnaryCall<protobuf::Empty, proto::PeersReply> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "PeersCall"});
    }
};

// rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
class PeerCountCall : public sw_rpc::server::UnaryCall<proto::PeerCountRequest, proto::PeerCountReply> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "PeerCountCall"});
    }
};

// rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
class PeerByIdCall : public sw_rpc::server::UnaryCall<proto::PeerByIdRequest, proto::PeerByIdReply> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "PeerByIdCall"});
    }
};

// rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
class PenalizePeerCall : public sw_rpc::server::UnaryCall<proto::PenalizePeerRequest, protobuf::Empty> {
  public:
    using Base::UnaryCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish_with_error(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "PenalizePeerCall"});
    }
};

// Subscribe to notifications about connected or lost peers.
// rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
class PeerEventsCall : public sw_rpc::server::ServerStreamingCall<proto::PeerEventsRequest, proto::PeerEvent> {
  public:
    using Base::ServerStreamingCall;

    awaitable<void> operator()(const ServiceState& /*state*/) {
        co_await agrpc::finish(responder_, grpc::Status{grpc::StatusCode::UNIMPLEMENTED, "PeerEventsCall"});
    }
};

class ServiceImpl final {
  public:
    explicit ServiceImpl(ServiceState state) : state_(state) {}

    void register_request_calls(
        agrpc::GrpcContext* grpc_context,
        ::sentry::Sentry::AsyncService* async_service) {
        request_repeatedly<SetStatusCall>(&AsyncService::RequestSetStatus, grpc_context, async_service);
        request_repeatedly<HandshakeCall>(&AsyncService::RequestHandShake, grpc_context, async_service);
        request_repeatedly<NodeInfoCall>(&AsyncService::RequestNodeInfo, grpc_context, async_service);

        request_repeatedly<SendMessageByIdCall>(&AsyncService::RequestSendMessageById, grpc_context, async_service);
        request_repeatedly<SendMessageToRandomPeersCall>(&AsyncService::RequestSendMessageToRandomPeers, grpc_context, async_service);
        request_repeatedly<SendMessageToAllCall>(&AsyncService::RequestSendMessageToAll, grpc_context, async_service);
        request_repeatedly<SendMessageByMinBlockCall>(&AsyncService::RequestSendMessageByMinBlock, grpc_context, async_service);
        request_repeatedly<PeerMinBlockCall>(&AsyncService::RequestPeerMinBlock, grpc_context, async_service);
        request_repeatedly<MessagesCall>(&AsyncService::RequestMessages, grpc_context, async_service);

        request_repeatedly<PeersCall>(&AsyncService::RequestPeers, grpc_context, async_service);
        request_repeatedly<PeerCountCall>(&AsyncService::RequestPeerCount, grpc_context, async_service);
        request_repeatedly<PeerByIdCall>(&AsyncService::RequestPeerById, grpc_context, async_service);
        request_repeatedly<PenalizePeerCall>(&AsyncService::RequestPenalizePeer, grpc_context, async_service);
        request_repeatedly<PeerEventsCall>(&AsyncService::RequestPeerEvents, grpc_context, async_service);
    }

  private:
    ServiceState state_;

    // Register one requested call repeatedly for each RPC: asio-grpc will take care of re-registration on any incoming call
    template <class RequestHandler, typename RPC>
    void request_repeatedly(
        RPC rpc,
        agrpc::GrpcContext* grpc_context,
        ::sentry::Sentry::AsyncService* async_service) {
        const auto& state = state_;
        sw_rpc::request_repeatedly(*grpc_context, async_service, rpc, [state](auto&&... args) -> boost::asio::awaitable<void> {
            co_await RequestHandler{std::forward<decltype(args)>(args)...}(state);
        });
    }
};

Service::Service(ServiceState state)
    : p_impl_(std::make_unique<ServiceImpl>(state)) {}

Service::~Service() {
    log::Trace() << "silkworm::sentry::Service::~Service";
}

void Service::register_request_calls(
    agrpc::GrpcContext* grpc_context,
    ::sentry::Sentry::AsyncService* async_service) {
    p_impl_->register_request_calls(grpc_context, async_service);
}

}  // namespace silkworm::sentry::rpc
