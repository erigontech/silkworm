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

#include "serial_node_db.hpp"

#include <boost/asio/use_awaitable.hpp>

#include <silkworm/infra/concurrency/co_spawn_sw.hpp>

namespace silkworm::sentry::discovery::node_db {

using namespace boost::asio;

Task<bool> SerialNodeDb::upsert_node_address(NodeId id, NodeAddress address) {
    return concurrency::co_spawn_sw(strand_, db_.upsert_node_address(std::move(id), std::move(address)), use_awaitable);
}

Task<std::optional<NodeAddress>> SerialNodeDb::find_node_address_v4(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_node_address_v4(std::move(id)), use_awaitable);
}

Task<std::optional<NodeAddress>> SerialNodeDb::find_node_address_v6(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_node_address_v6(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_next_ping_time(NodeId id, Time value) {
    return concurrency::co_spawn_sw(strand_, db_.update_next_ping_time(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<Time>> SerialNodeDb::find_next_ping_time(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_next_ping_time(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_last_pong_time(NodeId id, Time value) {
    return concurrency::co_spawn_sw(strand_, db_.update_last_pong_time(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<Time>> SerialNodeDb::find_last_pong_time(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_last_pong_time(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_ping_fails(NodeId id, size_t value) {
    return concurrency::co_spawn_sw(strand_, db_.update_ping_fails(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<size_t>> SerialNodeDb::find_ping_fails(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_ping_fails(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_peer_disconnected_time(NodeId id, Time value) {
    return concurrency::co_spawn_sw(strand_, db_.update_peer_disconnected_time(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<Time>> SerialNodeDb::find_peer_disconnected_time(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_peer_disconnected_time(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_peer_is_useless(NodeId id, bool value) {
    return concurrency::co_spawn_sw(strand_, db_.update_peer_is_useless(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<bool>> SerialNodeDb::find_peer_is_useless(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_peer_is_useless(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_distance(NodeId id, size_t value) {
    return concurrency::co_spawn_sw(strand_, db_.update_distance(std::move(id), value), use_awaitable);
}

Task<std::optional<size_t>> SerialNodeDb::find_distance(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.find_distance(std::move(id)), use_awaitable);
}

Task<std::vector<NodeId>> SerialNodeDb::find_ping_candidates(Time time, size_t limit) {
    return concurrency::co_spawn_sw(strand_, db_.find_ping_candidates(std::move(time), limit), use_awaitable);
}

Task<std::vector<NodeId>> SerialNodeDb::find_useful_nodes(Time min_pong_time, size_t limit) {
    return concurrency::co_spawn_sw(strand_, db_.find_useful_nodes(std::move(min_pong_time), limit), use_awaitable);
}

Task<std::vector<NodeId>> SerialNodeDb::find_lookup_candidates(FindLookupCandidatesQuery query) {
    return concurrency::co_spawn_sw(strand_, db_.find_lookup_candidates(std::move(query)), use_awaitable);
}

Task<void> SerialNodeDb::mark_taken_lookup_candidates(const std::vector<NodeId>& ids, Time time) {
    return concurrency::co_spawn_sw(strand_, db_.mark_taken_lookup_candidates(ids, std::move(time)), use_awaitable);
}

Task<std::vector<NodeId>> SerialNodeDb::take_lookup_candidates(FindLookupCandidatesQuery query, Time time) {
    return concurrency::co_spawn_sw(strand_, db_.take_lookup_candidates(std::move(query), std::move(time)), use_awaitable);
}

Task<std::vector<NodeId>> SerialNodeDb::find_peer_candidates(FindPeerCandidatesQuery query) {
    return concurrency::co_spawn_sw(strand_, db_.find_peer_candidates(std::move(query)), use_awaitable);
}

Task<void> SerialNodeDb::mark_taken_peer_candidates(const std::vector<NodeId>& ids, Time time) {
    return concurrency::co_spawn_sw(strand_, db_.mark_taken_peer_candidates(ids, std::move(time)), use_awaitable);
}

Task<std::vector<NodeId>> SerialNodeDb::take_peer_candidates(FindPeerCandidatesQuery query, Time time) {
    return concurrency::co_spawn_sw(strand_, db_.take_peer_candidates(std::move(query), std::move(time)), use_awaitable);
}

Task<void> SerialNodeDb::delete_node(NodeId id) {
    return concurrency::co_spawn_sw(strand_, db_.delete_node(std::move(id)), use_awaitable);
}

}  // namespace silkworm::sentry::discovery::node_db
