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

#include <chrono>
#include <optional>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/address.hpp>

#include <silkworm/sentry/common/ecc_public_key.hpp>

namespace silkworm::sentry::discovery::node_db {

using NodeId = EccPublicKey;
using Time = std::chrono::time_point<std::chrono::system_clock>;

struct NodeAddress {
    boost::asio::ip::address ip;
    uint16_t port_disc{};
    uint16_t port_rlpx{};
};

struct NodeDb {
    virtual ~NodeDb() = default;

    virtual Task<void> upsert_node_address(NodeId id, NodeAddress address) = 0;
    virtual Task<std::optional<NodeAddress>> find_node_address_v4(NodeId id) = 0;
    virtual Task<std::optional<NodeAddress>> find_node_address_v6(NodeId id) = 0;

    virtual Task<void> update_last_ping_time(NodeId id, Time value) = 0;
    virtual Task<std::optional<Time>> find_last_ping_time(NodeId id) = 0;

    virtual Task<void> update_last_pong_time(NodeId id, Time value) = 0;
    virtual Task<std::optional<Time>> find_last_pong_time(NodeId id) = 0;

    virtual Task<void> update_distance(NodeId id, size_t value) = 0;
    virtual Task<std::optional<size_t>> find_distance(NodeId id) = 0;

    virtual Task<void> delete_node(NodeId id) = 0;
};

}  // namespace silkworm::sentry::discovery::node_db
