// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <string>
#include <vector>

namespace silkworm::rpc {

struct PeerInfo {
    std::string id;
    std::string name;
    std::string enode;
    std::string enr;
    std::vector<std::string> caps;
    std::string local_address;
    std::string remote_address;
    bool is_connection_inbound{false};
    bool is_connection_trusted{false};
    bool is_connection_static{false};
};

using PeerInfos = std::vector<PeerInfo>;

}  // namespace silkworm::rpc
