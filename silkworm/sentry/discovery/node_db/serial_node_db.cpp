// Copyright 2025 The Silkworm Authors
// SPDX-License-Identifier: Apache-2.0

#include "serial_node_db.hpp"

#include <boost/asio/use_awaitable.hpp>

#include <silkworm/infra/concurrency/spawn.hpp>

namespace silkworm::sentry::discovery::node_db {

using namespace boost::asio;

Task<bool> SerialNodeDb::upsert_node_address(NodeId id, NodeAddress address) {
    return concurrency::spawn_task(strand_, db_.upsert_node_address(std::move(id), std::move(address)));
}

Task<std::optional<NodeAddress>> SerialNodeDb::find_node_address_v4(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_node_address_v4(std::move(id)));
}

Task<std::optional<NodeAddress>> SerialNodeDb::find_node_address_v6(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_node_address_v6(std::move(id)));
}

Task<void> SerialNodeDb::update_next_ping_time(NodeId id, Time value) {
    return concurrency::spawn_task(strand_, db_.update_next_ping_time(std::move(id), value));
}

Task<std::optional<Time>> SerialNodeDb::find_next_ping_time(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_next_ping_time(std::move(id)));
}

Task<void> SerialNodeDb::update_last_pong_time(NodeId id, Time value) {
    return concurrency::spawn_task(strand_, db_.update_last_pong_time(std::move(id), value));
}

Task<std::optional<Time>> SerialNodeDb::find_last_pong_time(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_last_pong_time(std::move(id)));
}

Task<void> SerialNodeDb::update_ping_fails(NodeId id, size_t value) {
    return concurrency::spawn_task(strand_, db_.update_ping_fails(std::move(id), value));
}

Task<std::optional<size_t>> SerialNodeDb::find_ping_fails(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_ping_fails(std::move(id)));
}

Task<void> SerialNodeDb::update_peer_disconnected_time(NodeId id, Time value) {
    return concurrency::spawn_task(strand_, db_.update_peer_disconnected_time(std::move(id), value));
}

Task<std::optional<Time>> SerialNodeDb::find_peer_disconnected_time(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_peer_disconnected_time(std::move(id)));
}

Task<void> SerialNodeDb::update_peer_is_useless(NodeId id, bool value) {
    return concurrency::spawn_task(strand_, db_.update_peer_is_useless(std::move(id), value));
}

Task<std::optional<bool>> SerialNodeDb::find_peer_is_useless(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_peer_is_useless(std::move(id)));
}

Task<void> SerialNodeDb::update_distance(NodeId id, size_t value) {
    return concurrency::spawn_task(strand_, db_.update_distance(std::move(id), value));
}

Task<std::optional<size_t>> SerialNodeDb::find_distance(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_distance(std::move(id)));
}

Task<void> SerialNodeDb::update_enr_seq_num(NodeId id, uint64_t value) {
    return concurrency::spawn_task(strand_, db_.update_enr_seq_num(std::move(id), value));
}

Task<std::optional<uint64_t>> SerialNodeDb::find_enr_seq_num(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_enr_seq_num(std::move(id)));
}

Task<void> SerialNodeDb::update_eth1_fork_id(NodeId id, std::optional<Bytes> value) {
    return concurrency::spawn_task(strand_, db_.update_eth1_fork_id(std::move(id), value));
}

Task<std::optional<Bytes>> SerialNodeDb::find_eth1_fork_id(NodeId id) {
    return concurrency::spawn_task(strand_, db_.find_eth1_fork_id(std::move(id)));
}

Task<std::vector<NodeId>> SerialNodeDb::find_ping_candidates(Time time, size_t limit) {
    return concurrency::spawn_task(strand_, db_.find_ping_candidates(time, limit));
}

Task<std::vector<NodeId>> SerialNodeDb::find_useful_nodes(Time min_pong_time, size_t limit) {
    return concurrency::spawn_task(strand_, db_.find_useful_nodes(min_pong_time, limit));
}

Task<std::vector<NodeId>> SerialNodeDb::find_lookup_candidates(FindLookupCandidatesQuery query) {
    return concurrency::spawn_task(strand_, db_.find_lookup_candidates(query));
}

Task<void> SerialNodeDb::mark_taken_lookup_candidates(const std::vector<NodeId>& ids, Time time) {
    return concurrency::spawn_task(strand_, db_.mark_taken_lookup_candidates(ids, time));
}

Task<std::vector<NodeId>> SerialNodeDb::take_lookup_candidates(FindLookupCandidatesQuery query, Time time) {
    return concurrency::spawn_task(strand_, db_.take_lookup_candidates(query, time));
}

Task<std::vector<NodeId>> SerialNodeDb::find_peer_candidates(FindPeerCandidatesQuery query) {
    return concurrency::spawn_task(strand_, db_.find_peer_candidates(std::move(query)));
}

Task<void> SerialNodeDb::mark_taken_peer_candidates(const std::vector<NodeId>& ids, Time time) {
    return concurrency::spawn_task(strand_, db_.mark_taken_peer_candidates(ids, time));
}

Task<std::vector<NodeId>> SerialNodeDb::take_peer_candidates(FindPeerCandidatesQuery query, Time time) {
    return concurrency::spawn_task(strand_, db_.take_peer_candidates(std::move(query), time));
}

Task<void> SerialNodeDb::delete_node(NodeId id) {
    return concurrency::spawn_task(strand_, db_.delete_node(std::move(id)));
}

}  // namespace silkworm::sentry::discovery::node_db
