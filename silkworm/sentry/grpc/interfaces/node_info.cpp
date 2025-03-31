// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_info.hpp"

#include <sstream>
#include <stdexcept>
#include <string>

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <silkworm/sentry/common/enode_url.hpp>

#include "peer_id.hpp"

namespace silkworm::sentry::grpc::interfaces {

boost::asio::ip::tcp::endpoint parse_endpoint(const std::string& address) {
    auto delimiter_pos = address.find_last_of(':');
    if ((delimiter_pos == std::string::npos) || (delimiter_pos == address.size() - 1)) {
        throw std::invalid_argument("address has no port specified");
    }

    auto ip_str = address.substr(0, delimiter_pos);
    auto port_str = address.substr(delimiter_pos + 1);

    auto ip = boost::asio::ip::make_address(ip_str);
    auto port = static_cast<uint16_t>(std::stoi(port_str));
    return {ip, port};
}

api::NodeInfo node_info_from_proto_node_info(const types::NodeInfoReply& info) {
    return api::NodeInfo{
        sentry::EnodeUrl{info.enode()},
        info.name(),
        parse_endpoint(info.listener_addr()),
        static_cast<uint16_t>(info.ports().listener()),
    };
}

types::NodeInfoReply proto_node_info_from_node_info(const api::NodeInfo& info) {
    types::NodeInfoReply reply;
    reply.set_id(peer_id_string_from_public_key(info.node_url.public_key()));
    reply.set_name(info.client_id);
    reply.set_enode(info.node_url.to_string());

    // TODO: NodeInfo.enr
    // reply.set_enr("TODO");

    reply.mutable_ports()->set_listener(info.rlpx_server_port);

    // TODO: NodeInfo.discovery_port
    // reply.mutable_ports()->set_discovery(0);

    std::ostringstream rlpx_server_listen_endpoint_str;
    rlpx_server_listen_endpoint_str << info.rlpx_server_listen_endpoint;
    reply.set_listener_addr(rlpx_server_listen_endpoint_str.str());

    return reply;
}

}  // namespace silkworm::sentry::grpc::interfaces
