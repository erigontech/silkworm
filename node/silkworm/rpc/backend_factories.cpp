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

EtherbaseFactory::EtherbaseFactory(const EthereumBackEnd& backend)
    : EtherbaseRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestEtherbase) {
    const auto etherbase = backend.etherbase();
    if (etherbase.has_value()) {
        const auto h160 = new_H160_address(etherbase.value());
        response_.set_allocated_address(h160);
    }
}

void EtherbaseFactory::process_rpc(EtherbaseRpc& rpc, const remote::EtherbaseRequest* request) {
    SILK_TRACE << "EtherbaseFactory::process_rpc START rpc: " << &rpc << " request: " << request;

    if (response_.has_address()) {
        const bool sent = rpc.send_response(response_);
        SILK_TRACE << "EtherbaseFactory::process_rpc END etherbase: " << to_hex(address_from_H160(response_.address())) << " sent: " << sent;
    } else {
        const grpc::Status error{grpc::StatusCode::INTERNAL, "etherbase must be explicitly specified"};
        rpc.finish_with_error(error);
        SILK_TRACE << "EtherbaseFactory::process_rpc END error: " << error;
    }
}

NetVersionFactory::NetVersionFactory(const EthereumBackEnd& backend)
    : NetVersionRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestNetVersion),
    chain_id_(backend.chain_id()) {
}

void NetVersionFactory::process_rpc(NetVersionRpc& rpc, const remote::NetVersionRequest* request) {
    SILK_TRACE << "NetVersionFactory::process_rpc rpc: " << &rpc << " request: " << request;

    remote::NetVersionReply response;
    response.set_id(chain_id_);
    const bool sent = rpc.send_response(response);

    SILK_TRACE << "NetVersionFactory::process_rpc rsp: " << &response << " chain_id: " << chain_id_ << " sent: " << sent;
}

NetPeerCountFactory::NetPeerCountFactory()
    : NetPeerCountRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestNetPeerCount) {
}

void NetPeerCountFactory::process_rpc(NetPeerCountRpc& rpc, const remote::NetPeerCountRequest* request) {
    SILK_TRACE << "NetPeerCountFactory::process_rpc rpc: " << &rpc << " request: " << request;

    remote::NetPeerCountReply response;
    // TODO(canepat): fill the response using Sentry config client list
    const bool sent = rpc.send_response(response);

    SILK_TRACE << "NetPeerCountFactory::process_rpc rsp: " << &response << " sent: " << sent;
}

BackEndVersionFactory::BackEndVersionFactory()
    : BackEndVersionRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestVersion) {
    response_.set_major(std::get<0>(kEthBackEndApiVersion));
    response_.set_minor(std::get<1>(kEthBackEndApiVersion));
    response_.set_patch(std::get<2>(kEthBackEndApiVersion));
}

void BackEndVersionFactory::process_rpc(BackEndVersionRpc& rpc, const google::protobuf::Empty* request) {
    SILK_TRACE << "BackEndVersionFactory::process_rpc rpc: " << &rpc << " request: " << request;

    const bool sent = rpc.send_response(response_);

    SILK_TRACE << "BackEndVersionFactory::process_rpc rsp: " << &response_ << " sent: " << sent;
}

ProtocolVersionFactory::ProtocolVersionFactory()
    : ProtocolVersionRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestProtocolVersion) {
    response_.set_id(kEthDevp2pProtocolVersion);
}

void ProtocolVersionFactory::process_rpc(ProtocolVersionRpc& rpc, const remote::ProtocolVersionRequest* request) {
    SILK_TRACE << "ProtocolVersionFactory::process_rpc rpc: " << &rpc << " request: " << request;

    const bool sent = rpc.send_response(response_);

    SILK_TRACE << "ProtocolVersionFactory::process_rpc rsp: " << &response_ << " sent: " << sent;
}

ClientVersionFactory::ClientVersionFactory(const EthereumBackEnd& backend)
    : ClientVersionRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestClientVersion) {
    response_.set_nodename(backend.node_name());
}

void ClientVersionFactory::process_rpc(ClientVersionRpc& rpc, const remote::ClientVersionRequest* request) {
    SILK_TRACE << "ClientVersionFactory::process_rpc rpc: " << &rpc << " request: " << request;

    const bool sent = rpc.send_response(response_);

    SILK_TRACE << "ClientVersionFactory::process_rpc rsp: " << &response_ << " sent: " << sent;
}

SubscribeFactory::SubscribeFactory()
    : SubscribeRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestSubscribe) {
}

void SubscribeFactory::process_rpc(SubscribeRpc& rpc, const remote::SubscribeRequest* request) {
    SILK_TRACE << "SubscribeFactory::process_rpc rpc: " << &rpc << " request: " << request;

    // TODO(canepat): remove this example and fill the correct stream responses
    remote::SubscribeReply response1;
    response1.set_type(remote::Event::PENDING_BLOCK);
    response1.set_data("001122");
    rpc.send_response(response1);
    remote::SubscribeReply response2;
    response2.set_type(remote::Event::PENDING_LOGS);
    response2.set_data("334455");
    rpc.send_response(response2);

    const bool closed = rpc.close();

    SILK_TRACE << "SubscribeFactory::process_rpc closed: " << closed;
}

NodeInfoFactory::NodeInfoFactory()
    : NodeInfoRpcFactory(
        [&](auto& rpc, const auto* request) { process_rpc(rpc, request); },
        &remote::ETHBACKEND::AsyncService::RequestNodeInfo) {
}

void NodeInfoFactory::process_rpc(NodeInfoRpc& rpc, const remote::NodesInfoRequest* request) {
    SILK_TRACE << "NodeInfoFactory::process_rpc rpc: " << &rpc << " request: " << request << " limit: " << request->limit();

    remote::NodesInfoReply response;
    // TODO(canepat): fill the response using Sentry config client list
    const bool sent = rpc.send_response(response);

    SILK_TRACE << "NodeInfoFactory::process_rpc rsp: " << &response << " sent: " << sent;
}

BackEndFactoryGroup::BackEndFactoryGroup(const EthereumBackEnd& backend)
    : etherbase_factory{backend}, net_version_factory{backend}, client_version_factory{backend} {
}

} // namespace silkworm::rpc
