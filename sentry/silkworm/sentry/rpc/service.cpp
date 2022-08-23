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

#include <silkworm/common/log.hpp>
#include <silkworm/rpc/server/call.hpp>
#include <silkworm/rpc/server/call_factory.hpp>

namespace silkworm::sentry::rpc {

using boost::asio::io_context;
namespace protobuf = google::protobuf;
namespace proto = ::sentry;
namespace proto_types = ::types;
using AsyncService = proto::Sentry::AsyncService;
namespace sw_rpc = silkworm::rpc;

// rpc SetStatus(StatusData) returns (SetStatusReply);
class SetStatusCall : public sw_rpc::UnaryRpc<AsyncService, proto::StatusData, proto::SetStatusReply> {
  public:
    SetStatusCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::StatusData, proto::SetStatusReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::StatusData* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// HandShake - pre-requirement for all Send* methods - returns ETH protocol version,
// without knowledge of protocol - impossible encode correct P2P message
// rpc HandShake(google.protobuf.Empty) returns (HandShakeReply);
class HandshakeCall : public sw_rpc::UnaryRpc<AsyncService, protobuf::Empty, proto::HandShakeReply> {
  public:
    HandshakeCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, protobuf::Empty, proto::HandShakeReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const protobuf::Empty* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// NodeInfo returns a collection of metadata known about the host.
// rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
class NodeInfoCall : public sw_rpc::UnaryRpc<AsyncService, protobuf::Empty, proto_types::NodeInfoReply> {
  public:
    NodeInfoCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, protobuf::Empty, proto_types::NodeInfoReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const protobuf::Empty* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
class SendMessageByIdCall : public sw_rpc::UnaryRpc<AsyncService, proto::SendMessageByIdRequest, proto::SentPeers> {
  public:
    SendMessageByIdCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::SendMessageByIdRequest, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::SendMessageByIdRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
class SendMessageToRandomPeersCall : public sw_rpc::UnaryRpc<AsyncService, proto::SendMessageToRandomPeersRequest, proto::SentPeers> {
  public:
    SendMessageToRandomPeersCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::SendMessageToRandomPeersRequest, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::SendMessageToRandomPeersRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
class SendMessageToAllCall : public sw_rpc::UnaryRpc<AsyncService, proto::OutboundMessageData, proto::SentPeers> {
  public:
    SendMessageToAllCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::OutboundMessageData, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::OutboundMessageData* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
class SendMessageByMinBlockCall : public sw_rpc::UnaryRpc<AsyncService, proto::SendMessageByMinBlockRequest, proto::SentPeers> {
  public:
    SendMessageByMinBlockCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::SendMessageByMinBlockRequest, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::SendMessageByMinBlockRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
class PeerMinBlockCall : public sw_rpc::UnaryRpc<AsyncService, proto::PeerMinBlockRequest, protobuf::Empty> {
  public:
    PeerMinBlockCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PeerMinBlockRequest, protobuf::Empty>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PeerMinBlockRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// Subscribe to receive messages.
// Calling multiple times with a different set of ids starts separate streams.
// It is possible to subscribe to the same set if ids more than once.
// rpc Messages(MessagesRequest) returns (stream InboundMessage);
class MessagesCall : public sw_rpc::ServerStreamingRpc<AsyncService, proto::MessagesRequest, proto::InboundMessage> {
  public:
    MessagesCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : ServerStreamingRpc<AsyncService, proto::MessagesRequest, proto::InboundMessage>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::MessagesRequest* /*request*/) override {
        const bool closed = close_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
        log::Trace() << "sentry::MessagesCall closed: " << closed;
    }
};

// rpc Peers(google.protobuf.Empty) returns (PeersReply);
class PeersCall : public sw_rpc::UnaryRpc<AsyncService, protobuf::Empty, proto::PeersReply> {
  public:
    PeersCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, protobuf::Empty, proto::PeersReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const protobuf::Empty* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
class PeerCountCall : public sw_rpc::UnaryRpc<AsyncService, proto::PeerCountRequest, proto::PeerCountReply> {
  public:
    PeerCountCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PeerCountRequest, proto::PeerCountReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PeerCountRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
class PeerByIdCall : public sw_rpc::UnaryRpc<AsyncService, proto::PeerByIdRequest, proto::PeerByIdReply> {
  public:
    PeerByIdCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PeerByIdRequest, proto::PeerByIdReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PeerByIdRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
class PenalizePeerCall : public sw_rpc::UnaryRpc<AsyncService, proto::PenalizePeerRequest, protobuf::Empty> {
  public:
    PenalizePeerCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PenalizePeerRequest, protobuf::Empty>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PenalizePeerRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// Subscribe to notifications about connected or lost peers.
// rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
class PeerEventsCall : public sw_rpc::ServerStreamingRpc<AsyncService, proto::PeerEventsRequest, proto::PeerEvent> {
  public:
    PeerEventsCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : ServerStreamingRpc<AsyncService, proto::PeerEventsRequest, proto::PeerEvent>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PeerEventsRequest* /*request*/) override {
        const bool closed = close_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
        log::Trace() << "sentry::PeerEventsCall closed: " << closed;
    }
};

class ServiceImpl final {
  public:
    void register_request_calls(
        boost::asio::io_context& scheduler,
        ::sentry::Sentry::AsyncService* async_service,
        grpc::ServerCompletionQueue* queue) {
        call_factory_set_status_.create_rpc(scheduler, async_service, queue);
        call_factory_handshake_.create_rpc(scheduler, async_service, queue);
        call_factory_node_info_.create_rpc(scheduler, async_service, queue);

        call_factory_send_message_by_id_.create_rpc(scheduler, async_service, queue);
        call_factory_send_message_to_random_peers_.create_rpc(scheduler, async_service, queue);
        call_factory_send_message_to_all_.create_rpc(scheduler, async_service, queue);
        call_factory_send_message_by_min_block_.create_rpc(scheduler, async_service, queue);
        call_factory_peer_min_block_.create_rpc(scheduler, async_service, queue);
        call_factory_messages_.create_rpc(scheduler, async_service, queue);

        call_factory_peers_.create_rpc(scheduler, async_service, queue);
        call_factory_peer_count_.create_rpc(scheduler, async_service, queue);
        call_factory_peer_by_id_.create_rpc(scheduler, async_service, queue);
        call_factory_penalize_peer_.create_rpc(scheduler, async_service, queue);
        call_factory_peer_events_.create_rpc(scheduler, async_service, queue);
    }

  private:
    struct SetStatusCallFactory : public sw_rpc::CallFactory<AsyncService, SetStatusCall> {
        SetStatusCallFactory() : sw_rpc::CallFactory<AsyncService, SetStatusCall>(&AsyncService::RequestSetStatus) {}
    } call_factory_set_status_;
    struct HandshakeCallFactory : public sw_rpc::CallFactory<AsyncService, HandshakeCall> {
        HandshakeCallFactory() : sw_rpc::CallFactory<AsyncService, HandshakeCall>(&AsyncService::RequestHandShake) {}
    } call_factory_handshake_;
    struct NodeInfoCallFactory : public sw_rpc::CallFactory<AsyncService, NodeInfoCall> {
        NodeInfoCallFactory() : sw_rpc::CallFactory<AsyncService, NodeInfoCall>(&AsyncService::RequestNodeInfo) {}
    } call_factory_node_info_;

    struct SendMessageByIdCallFactory : public sw_rpc::CallFactory<AsyncService, SendMessageByIdCall> {
        SendMessageByIdCallFactory() : sw_rpc::CallFactory<AsyncService, SendMessageByIdCall>(&AsyncService::RequestSendMessageById) {}
    } call_factory_send_message_by_id_;
    struct SendMessageToRandomPeersCallFactory : public sw_rpc::CallFactory<AsyncService, SendMessageToRandomPeersCall> {
        SendMessageToRandomPeersCallFactory() : sw_rpc::CallFactory<AsyncService, SendMessageToRandomPeersCall>(&AsyncService::RequestSendMessageToRandomPeers) {}
    } call_factory_send_message_to_random_peers_;
    struct SendMessageToAllCallFactory : public sw_rpc::CallFactory<AsyncService, SendMessageToAllCall> {
        SendMessageToAllCallFactory() : sw_rpc::CallFactory<AsyncService, SendMessageToAllCall>(&AsyncService::RequestSendMessageToAll) {}
    } call_factory_send_message_to_all_;
    struct SendMessageByMinBlockCallFactory : public sw_rpc::CallFactory<AsyncService, SendMessageByMinBlockCall> {
        SendMessageByMinBlockCallFactory() : sw_rpc::CallFactory<AsyncService, SendMessageByMinBlockCall>(&AsyncService::RequestSendMessageByMinBlock) {}
    } call_factory_send_message_by_min_block_;
    struct PeerMinBlockCallFactory : public sw_rpc::CallFactory<AsyncService, PeerMinBlockCall> {
        PeerMinBlockCallFactory() : sw_rpc::CallFactory<AsyncService, PeerMinBlockCall>(&AsyncService::RequestPeerMinBlock) {}
    } call_factory_peer_min_block_;
    struct MessagesCallFactory : public sw_rpc::CallFactory<AsyncService, MessagesCall> {
        MessagesCallFactory() : sw_rpc::CallFactory<AsyncService, MessagesCall>(&AsyncService::RequestMessages) {}
    } call_factory_messages_;

    struct PeersCallFactory : public sw_rpc::CallFactory<AsyncService, PeersCall> {
        PeersCallFactory() : sw_rpc::CallFactory<AsyncService, PeersCall>(&AsyncService::RequestPeers) {}
    } call_factory_peers_;
    struct PeerCountCallFactory : public sw_rpc::CallFactory<AsyncService, PeerCountCall> {
        PeerCountCallFactory() : sw_rpc::CallFactory<AsyncService, PeerCountCall>(&AsyncService::RequestPeerCount) {}
    } call_factory_peer_count_;
    struct PeerByIdCallFactory : public sw_rpc::CallFactory<AsyncService, PeerByIdCall> {
        PeerByIdCallFactory() : sw_rpc::CallFactory<AsyncService, PeerByIdCall>(&AsyncService::RequestPeerById) {}
    } call_factory_peer_by_id_;
    struct PenalizePeerCallFactory : public sw_rpc::CallFactory<AsyncService, PenalizePeerCall> {
        PenalizePeerCallFactory() : sw_rpc::CallFactory<AsyncService, PenalizePeerCall>(&AsyncService::RequestPenalizePeer) {}
    } call_factory_penalize_peer_;
    struct PeerEventsCallFactory : public sw_rpc::CallFactory<AsyncService, PeerEventsCall> {
        PeerEventsCallFactory() : sw_rpc::CallFactory<AsyncService, PeerEventsCall>(&AsyncService::RequestPeerEvents) {}
    } call_factory_peer_events_;
};

Service::Service() : p_impl_(std::make_unique<ServiceImpl>()) {}

Service::~Service() {
    log::Trace() << "silkworm::sentry::Service::~Service";
}

// Register one requested call for each RPC factory
void Service::register_request_calls(
    boost::asio::io_context& scheduler,
    ::sentry::Sentry::AsyncService* async_service,
    grpc::ServerCompletionQueue* queue) {
    p_impl_->register_request_calls(scheduler, async_service, queue);
}

}  // namespace silkworm::sentry::rpc
