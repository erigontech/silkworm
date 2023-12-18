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
