// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#pragma once

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/strand.hpp>

#include "node_db.hpp"

namespace silkworm::sentry::discovery::node_db {

class SerialNodeDb : public NodeDb {
  public:
    SerialNodeDb(
        NodeDb& db,
        const boost::asio::any_io_executor& executor)
        : db_(db),
          strand_(boost::asio::make_strand(executor)) {}
    ~SerialNodeDb() override = default;

    Task<bool> upsert_node_address(NodeId id, NodeAddress address) override;
    Task<std::optional<NodeAddress>> find_node_address_v4(NodeId id) override;
    Task<std::optional<NodeAddress>> find_node_address_v6(NodeId id) override;

    Task<void> update_next_ping_time(NodeId id, Time value) override;
    Task<std::optional<Time>> find_next_ping_time(NodeId id) override;

    Task<void> update_last_pong_time(NodeId id, Time value) override;
    Task<std::optional<Time>> find_last_pong_time(NodeId id) override;

    Task<void> update_ping_fails(NodeId id, size_t value) override;
    Task<std::optional<size_t>> find_ping_fails(NodeId id) override;

    Task<void> update_peer_disconnected_time(NodeId id, Time value) override;
    Task<std::optional<Time>> find_peer_disconnected_time(NodeId id) override;

    Task<void> update_peer_is_useless(NodeId id, bool value) override;
    Task<std::optional<bool>> find_peer_is_useless(NodeId id) override;

    Task<void> update_distance(NodeId id, size_t value) override;
    Task<std::optional<size_t>> find_distance(NodeId id) override;

    Task<void> update_enr_seq_num(NodeId id, uint64_t value) override;
    Task<std::optional<uint64_t>> find_enr_seq_num(NodeId id) override;

    Task<void> update_eth1_fork_id(NodeId id, std::optional<Bytes> value) override;
    Task<std::optional<Bytes>> find_eth1_fork_id(NodeId id) override;

    Task<std::vector<NodeId>> find_ping_candidates(Time time, size_t limit) override;
    Task<std::vector<NodeId>> find_useful_nodes(Time min_pong_time, size_t limit) override;

    Task<std::vector<NodeId>> find_lookup_candidates(FindLookupCandidatesQuery query) override;
    Task<void> mark_taken_lookup_candidates(const std::vector<NodeId>& ids, Time time) override;
    Task<std::vector<NodeId>> take_lookup_candidates(FindLookupCandidatesQuery query, Time time) override;

    Task<std::vector<NodeId>> find_peer_candidates(FindPeerCandidatesQuery query) override;
    Task<void> mark_taken_peer_candidates(const std::vector<NodeId>& ids, Time time) override;
    Task<std::vector<NodeId>> take_peer_candidates(FindPeerCandidatesQuery query, Time time) override;

    Task<void> delete_node(NodeId id) override;

  private:
    NodeDb& db_;
    boost::asio::strand<boost::asio::any_io_executor> strand_;
};

}  // namespace silkworm::sentry::discovery::node_db
