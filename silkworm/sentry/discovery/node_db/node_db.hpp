// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <chrono>
#include <optional>
#include <vector>

#include <silkworm/infra/concurrency/task.hpp>

#include <boost/asio/ip/address.hpp>

#include <silkworm/core/common/bytes.hpp>
#include <silkworm/sentry/common/ecc_public_key.hpp>
#include <silkworm/sentry/discovery/common/node_address.hpp>

namespace silkworm::sentry::discovery::node_db {

using NodeId = EccPublicKey;
using Time = std::chrono::time_point<std::chrono::system_clock>;

struct NodeAddress {
    boost::asio::ip::address ip;
    uint16_t port_disc{};
    uint16_t port_rlpx{};

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    NodeAddress(boost::asio::ip::address ip1) : ip(std::move(ip1)) {}

    NodeAddress(boost::asio::ip::address ip1, uint16_t port_disc1, uint16_t port_rlpx1)
        : ip(std::move(ip1)),
          port_disc(port_disc1),
          port_rlpx(port_rlpx1) {}

    // NOLINTNEXTLINE(google-explicit-constructor, hicpp-explicit-conversions)
    NodeAddress(const discovery::NodeAddress& address)
        : ip(address.endpoint.address()),
          port_disc(address.endpoint.port()),
          port_rlpx(address.port_rlpx) {}

    discovery::NodeAddress to_common_address() const {
        return {ip, port_disc, port_rlpx};
    }
};

struct NodeDb {
    virtual ~NodeDb() = default;

    virtual Task<bool> upsert_node_address(NodeId id, NodeAddress address) = 0;
    virtual Task<std::optional<NodeAddress>> find_node_address_v4(NodeId id) = 0;
    virtual Task<std::optional<NodeAddress>> find_node_address_v6(NodeId id) = 0;

    virtual Task<std::optional<NodeAddress>> find_node_address(NodeId id) {
        auto address = co_await find_node_address_v4(id);
        if (!address) {
            address = co_await find_node_address_v6(id);
        }
        co_return address;
    }

    virtual Task<void> update_next_ping_time(NodeId id, Time value) = 0;
    virtual Task<std::optional<Time>> find_next_ping_time(NodeId id) = 0;

    virtual Task<void> update_last_pong_time(NodeId id, Time value) = 0;
    virtual Task<std::optional<Time>> find_last_pong_time(NodeId id) = 0;

    virtual Task<void> update_ping_fails(NodeId id, size_t value) = 0;
    virtual Task<std::optional<size_t>> find_ping_fails(NodeId id) = 0;

    virtual Task<void> update_peer_disconnected_time(NodeId id, Time value) = 0;
    virtual Task<std::optional<Time>> find_peer_disconnected_time(NodeId id) = 0;

    virtual Task<void> update_peer_is_useless(NodeId id, bool value) = 0;
    virtual Task<std::optional<bool>> find_peer_is_useless(NodeId id) = 0;

    virtual Task<void> update_distance(NodeId id, size_t value) = 0;
    virtual Task<std::optional<size_t>> find_distance(NodeId id) = 0;

    virtual Task<void> update_enr_seq_num(NodeId id, uint64_t value) = 0;
    virtual Task<std::optional<uint64_t>> find_enr_seq_num(NodeId id) = 0;

    virtual Task<void> update_eth1_fork_id(NodeId id, std::optional<Bytes> value) = 0;
    virtual Task<std::optional<Bytes>> find_eth1_fork_id(NodeId id) = 0;

    virtual Task<std::vector<NodeId>> find_ping_candidates(Time time, size_t limit) = 0;
    virtual Task<std::vector<NodeId>> find_useful_nodes(Time min_pong_time, size_t limit) = 0;

    struct FindLookupCandidatesQuery {
        Time min_pong_time;
        Time max_lookup_time;
        size_t limit{};
    };

    virtual Task<std::vector<NodeId>> find_lookup_candidates(FindLookupCandidatesQuery query) = 0;
    virtual Task<void> mark_taken_lookup_candidates(const std::vector<NodeId>& ids, Time time) = 0;
    virtual Task<std::vector<NodeId>> take_lookup_candidates(FindLookupCandidatesQuery query, Time time) = 0;

    struct FindPeerCandidatesQuery {
        Time min_pong_time;
        Time max_peer_disconnected_time;
        Time max_taken_time;
        std::vector<NodeId> exclude_ids;
        size_t limit{};
    };

    virtual Task<std::vector<NodeId>> find_peer_candidates(FindPeerCandidatesQuery query) = 0;
    virtual Task<void> mark_taken_peer_candidates(const std::vector<NodeId>& ids, Time time) = 0;
    virtual Task<std::vector<NodeId>> take_peer_candidates(FindPeerCandidatesQuery query, Time time) = 0;

    virtual Task<void> delete_node(NodeId id) = 0;
};

}  // namespace silkworm::sentry::discovery::node_db
