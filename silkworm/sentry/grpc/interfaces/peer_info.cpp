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

#include "peer_info.hpp"

#include <sstream>
#include <string>
#include <vector>

#include <boost/asio/ip/tcp.hpp>

#include <silkworm/sentry/common/enode_url.hpp>

#include "peer_id.hpp"

namespace silkworm::sentry::grpc::interfaces {

boost::asio::ip::tcp::endpoint parse_endpoint(const std::string& address);

api::api_common::PeerInfo peer_info_from_proto_peer_info(const types::PeerInfo& info) {
    std::vector<std::string> capabilities;
    capabilities.reserve(static_cast<size_t>(info.caps_size()));
    for (auto& cap : info.caps()) {
        capabilities.push_back(cap);
    }

    return api::api_common::PeerInfo{
        sentry::common::EnodeUrl{info.enode()},
        peer_public_key_from_id_string(info.id()),
        parse_endpoint(info.conn_local_addr()),
        parse_endpoint(info.conn_remote_addr()),
        info.conn_is_inbound(),
        info.conn_is_static(),
        info.name(),
        capabilities,
    };
}

types::PeerInfo proto_peer_info_from_peer_info(const api::api_common::PeerInfo& peer) {
    types::PeerInfo info;
    info.set_id(peer_id_string_from_public_key(peer.peer_public_key));
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

api::api_common::PeerInfos peer_infos_from_proto_peers_reply(const ::sentry::PeersReply& reply) {
    api::api_common::PeerInfos result;
    for (auto& peer : reply.peers()) {
        result.push_back(peer_info_from_proto_peer_info(peer));
    }
    return result;
}

::sentry::PeersReply proto_peers_reply_from_peer_infos(const api::api_common::PeerInfos& peers) {
    ::sentry::PeersReply reply;
    for (auto& peer : peers) {
        reply.add_peers()->CopyFrom(proto_peer_info_from_peer_info(peer));
    }
    return reply;
}

std::optional<api::api_common::PeerInfo> peer_info_opt_from_proto_peer_reply(const ::sentry::PeerByIdReply& reply) {
    if (reply.has_peer()) {
        auto result = peer_info_from_proto_peer_info(reply.peer());
        return {result};
    } else {
        return std::nullopt;
    }
}

::sentry::PeerByIdReply proto_peer_reply_from_peer_info_opt(const std::optional<api::api_common::PeerInfo>& peer_opt) {
    ::sentry::PeerByIdReply reply;
    if (peer_opt) {
        reply.mutable_peer()->CopyFrom(proto_peer_info_from_peer_info(peer_opt.value()));
    }
    return reply;
}

}  // namespace silkworm::sentry::grpc::interfaces
