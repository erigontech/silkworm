// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_info.hpp"

namespace silkworm::rpc {

void to_json(nlohmann::json& json, const NodeInfoPorts& node_info_ports) {
    json["discovery"] = node_info_ports.discovery;
    json["listener"] = node_info_ports.listener;
}

void to_json(nlohmann::json& json, const NodeInfo& node_info) {
    json["id"] = node_info.id;
    json["name"] = node_info.name;
    json["enode"] = node_info.enode;
    json["enr"] = node_info.enr;
    json["listenAddr"] = node_info.listener_addr;
    json["ports"] = node_info.ports;
    json["ip"] = node_info.enode;
    json["protocols"] = nlohmann::json::parse(node_info.protocols, nullptr, /* allow_exceptions = */ false);
}

}  // namespace silkworm::rpc
