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

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_awaitable.hpp>

namespace silkworm::sentry::discovery::node_db {

using namespace boost::asio;

Task<void> SerialNodeDb::upsert_node_address(NodeId id, NodeAddress address) {
    return co_spawn(strand_, db_.upsert_node_address(std::move(id), std::move(address)), use_awaitable);
}

Task<std::optional<NodeAddress>> SerialNodeDb::find_node_address_v4(NodeId id) {
    return co_spawn(strand_, db_.find_node_address_v4(std::move(id)), use_awaitable);
}

Task<std::optional<NodeAddress>> SerialNodeDb::find_node_address_v6(NodeId id) {
    return co_spawn(strand_, db_.find_node_address_v6(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_last_ping_time(NodeId id, Time value) {
    return co_spawn(strand_, db_.update_last_ping_time(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<Time>> SerialNodeDb::find_last_ping_time(NodeId id) {
    return co_spawn(strand_, db_.find_last_ping_time(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::update_last_pong_time(NodeId id, Time value) {
    return co_spawn(strand_, db_.update_last_pong_time(std::move(id), std::move(value)), use_awaitable);
}

Task<std::optional<Time>> SerialNodeDb::find_last_pong_time(NodeId id) {
    return co_spawn(strand_, db_.find_last_pong_time(std::move(id)), use_awaitable);
}

Task<void> SerialNodeDb::delete_node(NodeId id) {
    return co_spawn(strand_, db_.delete_node(std::move(id)), use_awaitable);
}

}  // namespace silkworm::sentry::discovery::node_db
