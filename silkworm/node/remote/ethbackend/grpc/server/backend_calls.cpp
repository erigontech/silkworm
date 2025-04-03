// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "backend_calls.hpp"

#include <silkworm/core/types/address.hpp>
#include <silkworm/infra/common/log.hpp>
#include <silkworm/infra/grpc/client/call.hpp>
#include <silkworm/infra/grpc/common/conversion.hpp>
#include <silkworm/infra/grpc/common/util.hpp>
#include <silkworm/interfaces/types/types.pb.h>
#include <silkworm/sentry/grpc/interfaces/node_info.hpp>

namespace silkworm::ethbackend::grpc::server {

remote::EtherbaseReply EtherbaseCall::response_;

void EtherbaseCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    const auto etherbase = backend.etherbase();
    if (etherbase.has_value()) {
        const auto h160 = rpc::h160_from_address(etherbase.value()).release();
        EtherbaseCall::response_.set_allocated_address(h160);
    }
}

Task<void> EtherbaseCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "EtherbaseCall START";
    if (response_.has_address()) {
        co_await agrpc::finish(responder_, response_, ::grpc::Status::OK);
        SILK_TRACE << "EtherbaseCall END etherbase: " << rpc::address_from_h160(response_.address());
    } else {
        const ::grpc::Status error{::grpc::StatusCode::INTERNAL, "etherbase must be explicitly specified"};
        co_await agrpc::finish_with_error(responder_, error);
        SILK_TRACE << "EtherbaseCall END error: " << error;
    }
}

remote::NetVersionReply NetVersionCall::response_;

void NetVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    if (backend.chain_id()) {
        NetVersionCall::response_.set_id(*backend.chain_id());
    } else {
        NetVersionCall::response_.set_id(0);  // unused chain ID
    }
}

Task<void> NetVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "NetVersionCall START";
    co_await agrpc::finish(responder_, response_, ::grpc::Status::OK);
    SILK_TRACE << "NetVersionCall END chain_id: " << response_.id();
}

Task<void> NetPeerCountCall::operator()(const EthereumBackEnd& backend) {
    SILK_TRACE << "NetPeerCountCall START";

    auto sentry_client = backend.sentry_client();
    auto sentry = co_await sentry_client->service();

    remote::NetPeerCountReply response;
    ::grpc::Status result_status{::grpc::Status::OK};
    try {
        auto peer_count = co_await sentry->peer_count();
        response.set_count(peer_count);
        SILK_DEBUG << "Reply OK peer count = " << peer_count;
    } catch (const rpc::GrpcStatusError& status_error) {
        result_status = status_error.status();
        SILK_ERROR << "Reply KO result: " << result_status;
    }

    if (result_status.ok()) {
        co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
        SILK_TRACE << "NetPeerCountCall END count: " << response.count();
    } else {
        co_await agrpc::finish_with_error(responder_, result_status);
        SILK_TRACE << "NetPeerCountCall END error: " << result_status;
    }
}

types::VersionReply BackEndVersionCall::response_;

void BackEndVersionCall::fill_predefined_reply() {
    BackEndVersionCall::response_.set_major(std::get<0>(kEthBackEndApiVersion));
    BackEndVersionCall::response_.set_minor(std::get<1>(kEthBackEndApiVersion));
    BackEndVersionCall::response_.set_patch(std::get<2>(kEthBackEndApiVersion));
}

Task<void> BackEndVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "BackEndVersionCall START";
    co_await agrpc::finish(responder_, response_, ::grpc::Status::OK);
    SILK_TRACE << "BackEndVersionCall END version: " << response_.major() << "." << response_.minor() << "." << response_.patch();
}

remote::ProtocolVersionReply ProtocolVersionCall::response_;

void ProtocolVersionCall::fill_predefined_reply() {
    ProtocolVersionCall::response_.set_id(kEthDevp2pProtocolVersion);
}

Task<void> ProtocolVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "ProtocolVersionCall START";
    co_await agrpc::finish(responder_, response_, ::grpc::Status::OK);
    SILK_TRACE << "ProtocolVersionCall END id: " << response_.id();
}

remote::ClientVersionReply ClientVersionCall::response_;

void ClientVersionCall::fill_predefined_reply(const EthereumBackEnd& backend) {
    ClientVersionCall::response_.set_node_name(backend.node_name());
}

Task<void> ClientVersionCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "ClientVersionCall START";
    co_await agrpc::finish(responder_, response_, ::grpc::Status::OK);
    SILK_TRACE << "ClientVersionCall END node name: " << response_.node_name();
}

Task<void> SubscribeCall::operator()(const EthereumBackEnd& /*backend*/) {
    SILK_TRACE << "SubscribeCall START type: " << request_.type();

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::SubscribeReply response1;
    response1.set_type(remote::Event::PENDING_BLOCK);
    response1.set_data("001122");
    co_await agrpc::write(responder_, response1);
    remote::SubscribeReply response2;
    response2.set_type(remote::Event::PENDING_LOGS);
    response2.set_data("334455");
    co_await agrpc::write_and_finish(responder_, response2, ::grpc::WriteOptions{}, ::grpc::Status::OK);

    SILK_TRACE << "SubscribeCall END";
}

Task<void> NodeInfoCall::operator()(const EthereumBackEnd& backend) {
    SILK_TRACE << "NodeInfoCall START limit: " << request_.limit();

    auto sentry_client = backend.sentry_client();
    auto sentry = co_await sentry_client->service();

    remote::NodesInfoReply response;
    ::grpc::Status result_status{::grpc::Status::OK};
    try {
        auto node_infos = co_await sentry->node_infos();
        for (auto& node_info : node_infos) {
            SILK_DEBUG << "Reply OK node info: client_id=" << node_info.client_id;
            response.add_nodes_info()->CopyFrom(sentry::grpc::interfaces::proto_node_info_from_node_info(node_info));
        }
    } catch (const rpc::GrpcStatusError& status_error) {
        result_status = status_error.status();
        SILK_ERROR << "Reply KO result: " << result_status;
    }

    if (result_status.ok()) {
        co_await agrpc::finish(responder_, response, ::grpc::Status::OK);
        SILK_TRACE << "NodeInfoCall END #nodes: " << response.nodes_info_size();
    } else {
        co_await agrpc::finish_with_error(responder_, result_status);
        SILK_TRACE << "NodeInfoCall END error: " << result_status;
    }
}

}  // namespace silkworm::ethbackend::grpc::server
