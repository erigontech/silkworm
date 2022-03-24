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

#include "backend_factories.hpp"

#include <evmc/evmc.hpp>

#include <silkworm/common/endian.hpp>
#include <silkworm/common/log.hpp>
#include <silkworm/rpc/util.hpp>
#include <types/types.pb.h>

namespace silkworm::rpc {

inline static types::H128* new_H128_from_bytes(const uint8_t* bytes) {
    auto h128{new types::H128()};
    h128->set_hi(endian::load_big_u64(bytes));
    h128->set_lo(endian::load_big_u64(bytes + 8));
    return h128;
}

inline static types::H160* new_H160_address(const evmc::address& address) {
    auto h160{new types::H160()};
    auto hi{new_H128_from_bytes(address.bytes)};
    h160->set_allocated_hi(hi);
    h160->set_lo(endian::load_big_u32(address.bytes + 16));
    return h160;
}

remote::EtherbaseReply EtherbaseCall::response_;

void EtherbaseCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    const auto etherbase = backend.etherbase();
    if (etherbase.has_value()) {
        const auto h160 = new_H160_address(etherbase.value());
        EtherbaseCall::response_.set_allocated_address(h160);
    }
}

EtherbaseCall::EtherbaseCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, remote::EtherbaseRequest, remote::EtherbaseReply>(service, queue, handlers) {
}

void EtherbaseCall::process(const remote::EtherbaseRequest* request) {
    SILK_TRACE << "EtherbaseCall::process START request: " << request;

    if (response_.has_address()) {
        const bool sent = send_response(response_);
        SILK_TRACE << "EtherbaseCall::process END etherbase: " << to_hex(address_from_H160(response_.address())) << " sent: " << sent;
    } else {
        const grpc::Status error{grpc::StatusCode::INTERNAL, "etherbase must be explicitly specified"};
        finish_with_error(error);
        SILK_TRACE << "EtherbaseCall::process END error: " << error;
    }
}

EtherbaseCallFactory::EtherbaseCallFactory(const EthereumBackEnd& backend)
    : Factory<remote::ETHBACKEND::AsyncService, EtherbaseCall>(&remote::ETHBACKEND::AsyncService::RequestEtherbase) {
    EtherbaseCall::fill_predefined_reply(backend);
}

remote::NetVersionReply NetVersionCall::response_;

void NetVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    NetVersionCall::response_.set_id(backend.chain_id());
}

NetVersionCall::NetVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetVersionRequest, remote::NetVersionReply>(service, queue, handlers) {
}

void NetVersionCall::process(const remote::NetVersionRequest* request) {
    SILK_TRACE << "NetVersionCall::process request: " << request;

    const bool sent = send_response(response_);

    SILK_TRACE << "NetVersionCall::process chain_id: " << response_.id() << " sent: " << sent;
}

NetVersionCallFactory::NetVersionCallFactory(const EthereumBackEnd& backend)
    : Factory<remote::ETHBACKEND::AsyncService, NetVersionCall>(&remote::ETHBACKEND::AsyncService::RequestNetVersion) {
    NetVersionCall::fill_predefined_reply(backend);
}

std::set<SentryClient*> NetPeerCountCall::sentries_;

void NetPeerCountCall::add_sentry(SentryClient* sentry) {
    NetPeerCountCall::sentries_.insert(sentry);
}

void NetPeerCountCall::remove_sentry(SentryClient* sentry) {
    NetPeerCountCall::sentries_.erase(sentry);
}

NetPeerCountCall::NetPeerCountCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NetPeerCountRequest, remote::NetPeerCountReply>(service, queue, handlers) {
}

void NetPeerCountCall::process(const remote::NetPeerCountRequest* request) {
    SILK_TRACE << "NetPeerCountCall::process START request: " << request;

    if (sentries_.size() == 0) {
        remote::NetPeerCountReply response;
        const bool sent = send_response(response);
        SILK_TRACE << "NetPeerCountCall::process END count: 0 sent: " << sent;
        return;
    }

    SILK_DEBUG << "NetPeerCountCall::process num sentries: " << sentries_.size();

    expected_responses_ = sentries_.size();

    for (const auto& sentry : sentries_) {
        sentry->peer_count([&](const grpc::Status status, const sentry::PeerCountReply& reply) {
            --expected_responses_;

            SILK_DEBUG << "Peer count replies: [" << (sentries_.size()-expected_responses_) << "/" << sentries_.size() << "]";

            if (status.ok()) {
                uint64_t count = reply.count();
                total_count_ += count;
                SILK_DEBUG << "Reply OK peer count: partial=" << count << " total=" << total_count_;
            } else {
                result_status_ = status;
                SILK_DEBUG << "Reply KO result: " << result_status_;
            }

            if (expected_responses_ == 0) {
                if (result_status_.ok()) {
                    remote::NetPeerCountReply response;
                    response.set_count(total_count_);
                    const bool sent = send_response(response);
                    SILK_TRACE << "NetPeerCountCall::process END count: " << total_count_ << " sent: " << sent;
                } else {
                    finish_with_error(result_status_);
                    SILK_TRACE << "NetPeerCountCall::process END error: " << result_status_;
                }
            }
        });
    }
}

NetPeerCountCallFactory::NetPeerCountCallFactory()
    : Factory<remote::ETHBACKEND::AsyncService, NetPeerCountCall>(&remote::ETHBACKEND::AsyncService::RequestNetPeerCount) {
}

types::VersionReply BackEndVersionCall::response_;

void BackEndVersionCall::fill_predefined_reply() {
    BackEndVersionCall::response_.set_major(std::get<0>(kEthBackEndApiVersion));
    BackEndVersionCall::response_.set_minor(std::get<1>(kEthBackEndApiVersion));
    BackEndVersionCall::response_.set_patch(std::get<2>(kEthBackEndApiVersion));
}

BackEndVersionCall::BackEndVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, google::protobuf::Empty, types::VersionReply>(service, queue, handlers) {
}

void BackEndVersionCall::process(const google::protobuf::Empty* request) {
    SILK_TRACE << "BackEndVersionCall::process request: " << request;

    const bool sent = send_response(response_);

    SILK_TRACE << "BackEndVersionCall::process rsp: " << &response_ << " sent: " << sent;
}

BackEndVersionCallFactory::BackEndVersionCallFactory()
    : Factory<remote::ETHBACKEND::AsyncService, BackEndVersionCall>(&remote::ETHBACKEND::AsyncService::RequestVersion) {
    BackEndVersionCall::fill_predefined_reply();
}

remote::ProtocolVersionReply ProtocolVersionCall::response_;

void ProtocolVersionCall::fill_predefined_reply() {
    ProtocolVersionCall::response_.set_id(kEthDevp2pProtocolVersion);
}

ProtocolVersionCall::ProtocolVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ProtocolVersionRequest, remote::ProtocolVersionReply>(service, queue, handlers) {
}

void ProtocolVersionCall::process(const remote::ProtocolVersionRequest* request) {
    SILK_TRACE << "ProtocolVersionCall::process request: " << request;

    const bool sent = send_response(response_);

    SILK_TRACE << "ProtocolVersionCall::process rsp: " << &response_ << " sent: " << sent;
}

ProtocolVersionCallFactory::ProtocolVersionCallFactory()
    : Factory<remote::ETHBACKEND::AsyncService, ProtocolVersionCall>(&remote::ETHBACKEND::AsyncService::RequestProtocolVersion) {
    ProtocolVersionCall::fill_predefined_reply();
}

remote::ClientVersionReply ClientVersionCall::response_;

void ClientVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    ClientVersionCall::response_.set_nodename(backend.node_name());
}

ClientVersionCall::ClientVersionCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, remote::ClientVersionRequest, remote::ClientVersionReply>(service, queue, handlers) {
}

void ClientVersionCall::process(const remote::ClientVersionRequest* request) {
    SILK_TRACE << "ClientVersionCall::process request: " << request;

    const bool sent = send_response(response_);

    SILK_TRACE << "ClientVersionCall::process rsp: " << &response_ << " sent: " << sent;
}

ClientVersionCallFactory::ClientVersionCallFactory(const EthereumBackEnd& backend)
    : Factory<remote::ETHBACKEND::AsyncService, ClientVersionCall>(&remote::ETHBACKEND::AsyncService::RequestClientVersion) {
    ClientVersionCall::fill_predefined_reply(backend);
}

SubscribeCall::SubscribeCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : ServerStreamingRpc<remote::ETHBACKEND::AsyncService, remote::SubscribeRequest, remote::SubscribeReply>(service, queue, handlers) {
}

void SubscribeCall::process(const remote::SubscribeRequest* request) {
    SILK_TRACE << "SubscribeCall::process request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::SubscribeReply response1;
    response1.set_type(remote::Event::PENDING_BLOCK);
    response1.set_data("001122");
    send_response(response1);
    remote::SubscribeReply response2;
    response2.set_type(remote::Event::PENDING_LOGS);
    response2.set_data("334455");
    send_response(response2);

    const bool closed = close();

    SILK_TRACE << "SubscribeCall::process closed: " << closed;
}

SubscribeCallFactory::SubscribeCallFactory()
    : Factory<remote::ETHBACKEND::AsyncService, SubscribeCall>(&remote::ETHBACKEND::AsyncService::RequestSubscribe) {
}

std::set<SentryClient*> NodeInfoCall::sentries_;

void NodeInfoCall::add_sentry(SentryClient* sentry) {
    NodeInfoCall::sentries_.insert(sentry);
}

void NodeInfoCall::remove_sentry(SentryClient* sentry) {
    NodeInfoCall::sentries_.erase(sentry);
}

NodeInfoCall::NodeInfoCall(remote::ETHBACKEND::AsyncService* service, grpc::ServerCompletionQueue* queue, Handlers handlers)
    : UnaryRpc<remote::ETHBACKEND::AsyncService, remote::NodesInfoRequest, remote::NodesInfoReply>(service, queue, handlers) {
}

void NodeInfoCall::process(const remote::NodesInfoRequest* request) {
    SILK_TRACE << "NodeInfoCall::process request: " << request << " limit: " << request->limit();

    if (sentries_.size() == 0) {
        remote::NodesInfoReply response;
        const bool sent = send_response(response);
        SILK_TRACE << "NodeInfoCall::process END #nodes: 0 sent: " << sent;
        return;
    }

    expected_responses_ = sentries_.size();

    for (const auto& sentry : sentries_) {
        sentry->node_info([&](const grpc::Status status, const types::NodeInfoReply& reply) {
            --expected_responses_;

            if (status.ok()) {
                types::NodeInfoReply* nodes_info = response_.add_nodesinfo();
                *nodes_info = reply;
            } else {
                result_status_ = status;
            }

            if (expected_responses_ == 0) {
                if (result_status_.ok()) {
                    const bool sent = send_response(response_);
                    SILK_TRACE << "NodeInfoCall::process END #nodes: " << response_.nodesinfo_size() << " sent: " << sent;
                } else {
                    finish_with_error(result_status_);
                    SILK_TRACE << "NodeInfoCall::process END error: " << result_status_;
                }
            }
        });
    }
}

NodeInfoCallFactory::NodeInfoCallFactory()
    : Factory<remote::ETHBACKEND::AsyncService, NodeInfoCall>(&remote::ETHBACKEND::AsyncService::RequestNodeInfo) {
}

BackEndFactoryGroup::BackEndFactoryGroup(const EthereumBackEnd& backend)
    : etherbase_factory{backend}, net_version_factory{backend}, client_version_factory{backend} {
}

void BackEndFactoryGroup::add_sentry(std::unique_ptr<SentryClient>&& sentry) {
    NetPeerCountCall::add_sentry(sentry.get());
    NodeInfoCall::add_sentry(sentry.get());
    sentries_.push_back(std::move(sentry));
}

BackEndFactoryGroup::~BackEndFactoryGroup() {
    for (const auto& sentry : sentries_) {
        NetPeerCountCall::remove_sentry(sentry.get());
        NodeInfoCall::remove_sentry(sentry.get());
    }
}

} // namespace silkworm::rpc
