/*
Copyright 2020-2022 The Silkworm Authors

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

namespace silkworm::sentry {

using boost::asio::io_context;
namespace protobuf = google::protobuf;
namespace proto = ::sentry;
namespace proto_types = ::types;
using AsyncService = proto::Sentry::AsyncService;

// rpc SetStatus(StatusData) returns (SetStatusReply);
class SetStatusCall : public rpc::UnaryRpc<AsyncService, proto::StatusData, proto::SetStatusReply> {
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
class HandshakeCall : public rpc::UnaryRpc<AsyncService, protobuf::Empty, proto::HandShakeReply> {
  public:
    HandshakeCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, protobuf::Empty, proto::HandShakeReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const protobuf::Empty* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// NodeInfo returns a collection of metadata known about the host.
// rpc NodeInfo(google.protobuf.Empty) returns(types.NodeInfoReply);
class NodeInfoCall : public rpc::UnaryRpc<AsyncService, protobuf::Empty, proto_types::NodeInfoReply> {
  public:
    NodeInfoCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, protobuf::Empty, proto_types::NodeInfoReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const protobuf::Empty* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageById(SendMessageByIdRequest) returns (SentPeers);
class SendMessageByIdCall : public rpc::UnaryRpc<AsyncService, proto::SendMessageByIdRequest, proto::SentPeers> {
  public:
    SendMessageByIdCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::SendMessageByIdRequest, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::SendMessageByIdRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageToRandomPeers(SendMessageToRandomPeersRequest) returns (SentPeers);
class SendMessageToRandomPeersCall : public rpc::UnaryRpc<AsyncService, proto::SendMessageToRandomPeersRequest, proto::SentPeers> {
  public:
    SendMessageToRandomPeersCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::SendMessageToRandomPeersRequest, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::SendMessageToRandomPeersRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageToAll(OutboundMessageData) returns (SentPeers);
class SendMessageToAllCall : public rpc::UnaryRpc<AsyncService, proto::OutboundMessageData, proto::SentPeers> {
  public:
    SendMessageToAllCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::OutboundMessageData, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::OutboundMessageData* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc SendMessageByMinBlock(SendMessageByMinBlockRequest) returns (SentPeers);
class SendMessageByMinBlockCall : public rpc::UnaryRpc<AsyncService, proto::SendMessageByMinBlockRequest, proto::SentPeers> {
  public:
    SendMessageByMinBlockCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::SendMessageByMinBlockRequest, proto::SentPeers>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::SendMessageByMinBlockRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PeerMinBlock(PeerMinBlockRequest) returns (google.protobuf.Empty);
class PeerMinBlockCall : public rpc::UnaryRpc<AsyncService, proto::PeerMinBlockRequest, protobuf::Empty> {
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
class MessagesCall : public rpc::ServerStreamingRpc<AsyncService, proto::MessagesRequest, proto::InboundMessage> {
  public:
    MessagesCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : ServerStreamingRpc<AsyncService, proto::MessagesRequest, proto::InboundMessage>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::MessagesRequest* /*request*/) override {
        const bool closed = close_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
        log::Trace() << "sentry::MessagesCall closed: " << closed;
    }
};

// rpc Peers(google.protobuf.Empty) returns (PeersReply);
class PeersCall : public rpc::UnaryRpc<AsyncService, protobuf::Empty, proto::PeersReply> {
  public:
    PeersCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, protobuf::Empty, proto::PeersReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const protobuf::Empty* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PeerCount(PeerCountRequest) returns (PeerCountReply);
class PeerCountCall : public rpc::UnaryRpc<AsyncService, proto::PeerCountRequest, proto::PeerCountReply> {
  public:
    PeerCountCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PeerCountRequest, proto::PeerCountReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PeerCountRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PeerById(PeerByIdRequest) returns (PeerByIdReply);
class PeerByIdCall : public rpc::UnaryRpc<AsyncService, proto::PeerByIdRequest, proto::PeerByIdReply> {
  public:
    PeerByIdCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PeerByIdRequest, proto::PeerByIdReply>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PeerByIdRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// rpc PenalizePeer(PenalizePeerRequest) returns (google.protobuf.Empty);
class PenalizePeerCall : public rpc::UnaryRpc<AsyncService, proto::PenalizePeerRequest, protobuf::Empty> {
  public:
    PenalizePeerCall(io_context& scheduler, AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
        : UnaryRpc<AsyncService, proto::PenalizePeerRequest, protobuf::Empty>(scheduler, service, queue, std::move(handlers)) {}
    void process(const proto::PenalizePeerRequest* /*request*/) override {
        finish_with_error(grpc::Status{grpc::StatusCode::UNIMPLEMENTED, ""});
    }
};

// Subscribe to notifications about connected or lost peers.
// rpc PeerEvents(PeerEventsRequest) returns (stream PeerEvent);
class PeerEventsCall : public rpc::ServerStreamingRpc<AsyncService, proto::PeerEventsRequest, proto::PeerEvent> {
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
    struct SetStatusCallFactory : public rpc::CallFactory<AsyncService, SetStatusCall> {
        SetStatusCallFactory() : rpc::CallFactory<AsyncService, SetStatusCall>(&AsyncService::RequestSetStatus) {}
    } call_factory_set_status_;
    struct HandshakeCallFactory : public rpc::CallFactory<AsyncService, HandshakeCall> {
        HandshakeCallFactory() : rpc::CallFactory<AsyncService, HandshakeCall>(&AsyncService::RequestHandShake) {}
    } call_factory_handshake_;
    struct NodeInfoCallFactory : public rpc::CallFactory<AsyncService, NodeInfoCall> {
        NodeInfoCallFactory() : rpc::CallFactory<AsyncService, NodeInfoCall>(&AsyncService::RequestNodeInfo) {}
    } call_factory_node_info_;

    struct SendMessageByIdCallFactory : public rpc::CallFactory<AsyncService, SendMessageByIdCall> {
        SendMessageByIdCallFactory() : rpc::CallFactory<AsyncService, SendMessageByIdCall>(&AsyncService::RequestSendMessageById) {}
    } call_factory_send_message_by_id_;
    struct SendMessageToRandomPeersCallFactory : public rpc::CallFactory<AsyncService, SendMessageToRandomPeersCall> {
        SendMessageToRandomPeersCallFactory() : rpc::CallFactory<AsyncService, SendMessageToRandomPeersCall>(&AsyncService::RequestSendMessageToRandomPeers) {}
    } call_factory_send_message_to_random_peers_;
    struct SendMessageToAllCallFactory : public rpc::CallFactory<AsyncService, SendMessageToAllCall> {
        SendMessageToAllCallFactory() : rpc::CallFactory<AsyncService, SendMessageToAllCall>(&AsyncService::RequestSendMessageToAll) {}
    } call_factory_send_message_to_all_;
    struct SendMessageByMinBlockCallFactory : public rpc::CallFactory<AsyncService, SendMessageByMinBlockCall> {
        SendMessageByMinBlockCallFactory() : rpc::CallFactory<AsyncService, SendMessageByMinBlockCall>(&AsyncService::RequestSendMessageByMinBlock) {}
    } call_factory_send_message_by_min_block_;
    struct PeerMinBlockCallFactory : public rpc::CallFactory<AsyncService, PeerMinBlockCall> {
        PeerMinBlockCallFactory() : rpc::CallFactory<AsyncService, PeerMinBlockCall>(&AsyncService::RequestPeerMinBlock) {}
    } call_factory_peer_min_block_;
    struct MessagesCallFactory : public rpc::CallFactory<AsyncService, MessagesCall> {
        MessagesCallFactory() : rpc::CallFactory<AsyncService, MessagesCall>(&AsyncService::RequestMessages) {}
    } call_factory_messages_;

    struct PeersCallFactory : public rpc::CallFactory<AsyncService, PeersCall> {
        PeersCallFactory() : rpc::CallFactory<AsyncService, PeersCall>(&AsyncService::RequestPeers) {}
    } call_factory_peers_;
    struct PeerCountCallFactory : public rpc::CallFactory<AsyncService, PeerCountCall> {
        PeerCountCallFactory() : rpc::CallFactory<AsyncService, PeerCountCall>(&AsyncService::RequestPeerCount) {}
    } call_factory_peer_count_;
    struct PeerByIdCallFactory : public rpc::CallFactory<AsyncService, PeerByIdCall> {
        PeerByIdCallFactory() : rpc::CallFactory<AsyncService, PeerByIdCall>(&AsyncService::RequestPeerById) {}
    } call_factory_peer_by_id_;
    struct PenalizePeerCallFactory : public rpc::CallFactory<AsyncService, PenalizePeerCall> {
        PenalizePeerCallFactory() : rpc::CallFactory<AsyncService, PenalizePeerCall>(&AsyncService::RequestPenalizePeer) {}
    } call_factory_penalize_peer_;
    struct PeerEventsCallFactory : public rpc::CallFactory<AsyncService, PeerEventsCall> {
        PeerEventsCallFactory() : rpc::CallFactory<AsyncService, PeerEventsCall>(&AsyncService::RequestPeerEvents) {}
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

}  // namespace silkworm::sentry
