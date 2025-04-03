// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "peer_info.hpp"

#include <sstream>
#include <string>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include <silkworm/sentry/common/enode_url.hpp>

#include "peer_id.hpp"

namespace silkworm::sentry::grpc::interfaces {

boost::asio::ip::tcp::endpoint parse_endpoint(const std::string& address);

api::PeerInfo peer_info_from_proto_peer_info(const types::PeerInfo& info) {
    std::vector<std::string> capabilities;
    capabilities.reserve(static_cast<size_t>(info.caps_size()));
    for (auto& cap : info.caps()) {
        capabilities.push_back(cap);
    }

    return api::PeerInfo{
        sentry::EnodeUrl{info.enode()},
        parse_endpoint(info.conn_local_addr()),
        parse_endpoint(info.conn_remote_addr()),
        info.conn_is_inbound(),
        info.conn_is_static(),
        info.name(),
        capabilities,
    };
}

types::PeerInfo proto_peer_info_from_peer_info(const api::PeerInfo& peer) {
    types::PeerInfo info;
    info.set_id(peer_id_string_from_public_key(peer.url.public_key()));
    info.set_name(peer.client_id);
    info.set_enode(peer.url.to_string());

    // TODO: PeerInfo.enr
    // info.set_enr("TODO");

    for (auto& capability : peer.capabilities) {
        info.add_caps(capability);
    }

    std::ostringstream local_endpoint_str;
    local_endpoint_str << peer.local_endpoint;
    info.set_conn_local_addr(local_endpoint_str.str());

    std::ostringstream remote_endpoint_str;
    remote_endpoint_str << peer.remote_endpoint;
    info.set_conn_remote_addr(remote_endpoint_str.str());

    info.set_conn_is_inbound(peer.is_inbound);
    info.set_conn_is_trusted(false);
    info.set_conn_is_static(peer.is_static);
    return info;
}

api::PeerInfos peer_infos_from_proto_peers_reply(const ::sentry::PeersReply& reply) {
    api::PeerInfos result;
    for (auto& peer : reply.peers()) {
        result.push_back(peer_info_from_proto_peer_info(peer));
    }
    return result;
}

::sentry::PeersReply proto_peers_reply_from_peer_infos(const api::PeerInfos& peers) {
    ::sentry::PeersReply reply;
    for (auto& peer : peers) {
        reply.add_peers()->CopyFrom(proto_peer_info_from_peer_info(peer));
    }
    return reply;
}

std::optional<api::PeerInfo> peer_info_opt_from_proto_peer_reply(const ::sentry::PeerByIdReply& reply) {
    if (!reply.has_peer()) {
        return std::nullopt;
    }
    return peer_info_from_proto_peer_info(reply.peer());
}

::sentry::PeerByIdReply proto_peer_reply_from_peer_info_opt(const std::optional<api::PeerInfo>& peer_opt) {
    ::sentry::PeerByIdReply reply;
    if (peer_opt) {
        reply.mutable_peer()->CopyFrom(proto_peer_info_from_peer_info(peer_opt.value()));
    }
    return reply;
}

}  // namespace silkworm::sentry::grpc::interfaces
