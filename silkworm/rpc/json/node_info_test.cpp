// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "node_info.hpp"

#include <catch2/catch_test_macros.hpp>
#include <evmc/evmc.hpp>

namespace silkworm::rpc {

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
