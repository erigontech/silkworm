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

#include <catch2/catch.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

using Catch::Matchers::Message;
using evmc::literals::operator""_address, evmc::literals::operator""_bytes32;

TEST_CASE("serialize NodeInfoPorts", "[silkworm::json][to_json]") {
    silkworm::rpc::NodeInfoPorts ports{6, 7};
    nlohmann::json j = ports;
    CHECK(j == R"({
        "discovery":6,
        "listener":7
    })"_json);
}

TEST_CASE("serialize NodeInfo", "[silkworm::json][to_json]") {
    silkworm::rpc::NodeInfo node_info{"340", "erigon", "enode", "enr", "[::]:30303", R"({"eth": {"network":5, "difficulty":10790000}})"};
    nlohmann::json j = node_info;
    CHECK(j == R"( {
              "enode":"enode",
              "enr":"enr",
              "id":"340",
              "ip":"enode",
              "listenAddr":"[::]:30303",
              "name":"erigon",
              "ports":{"discovery":0,"listener":0},
              "protocols":  { "eth":  {"network":5, "difficulty":10790000}}
    })"_json);
}

}  // namespace silkworm::rpc
