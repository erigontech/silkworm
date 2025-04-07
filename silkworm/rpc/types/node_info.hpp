// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

namespace silkworm::rpc {

struct NodeInfoPorts {
    uint64_t discovery{0};
    uint64_t listener{0};
};

struct NodeInfo {
    std::string id;
    std::string name;
    std::string enode;
    std::string enr;
    std::string listener_addr;
    std::string protocols;
    NodeInfoPorts ports;
};

using NodeInfos = std::vector<NodeInfo>;

}  // namespace silkworm::rpc
