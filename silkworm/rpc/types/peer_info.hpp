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
