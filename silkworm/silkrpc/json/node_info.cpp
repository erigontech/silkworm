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
