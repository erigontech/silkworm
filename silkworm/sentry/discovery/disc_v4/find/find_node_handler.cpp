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

#include "find_node_handler.hpp"

#include <chrono>
#include <map>

#include <boost/system/errc.hpp>
#include <boost/system/system_error.hpp>

#include <silkworm/infra/common/log.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_address.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_distance.hpp>
#include <silkworm/sentry/discovery/disc_v4/ping/ping_check.hpp>

#include "neighbors_message.hpp"

namespace silkworm::sentry::discovery::disc_v4::find {

Task<void> FindNodeHandler::handle(
    FindNodeMessage message,
    EccPublicKey sender_public_key,
    boost::asio::ip::udp::endpoint sender_endpoint,
    MessageSender& sender,
    node_db::NodeDb& db) {
    if (is_expired_message_expiration(message.expiration)) {
        co_return;
    }

    // check that the sender has a valid pong
    auto last_pong_time = co_await db.find_last_pong_time(sender_public_key);
    auto now = std::chrono::system_clock::system_clock::now();
    if (!last_pong_time || (*last_pong_time < ping::min_valid_pong_time(now))) {
        co_return;
    }

    // find a bunch of nodes to choose from sorted by distance to the target_public_key
    std::multimap<size_t, EccPublicKey> node_ids_by_distance;
    for (auto& node_id : co_await db.find_useful_nodes(ping::min_valid_pong_time(now), 100)) {
        auto distance = node_distance(message.target_public_key, node_id);
        node_ids_by_distance.insert({distance, node_id});
    }

    // collect several nodes closest to the target_public_key
    std::vector<EccPublicKey> node_ids;
    for (auto& entry : node_ids_by_distance) {
        node_ids.push_back(entry.second);
        if (node_ids.size() >= 12)
            break;
    }

    // find addresses
    std::map<EccPublicKey, NodeAddress> node_addresses;
    for (auto& node_id : node_ids) {
        auto address = co_await db.find_node_address_v4(node_id);
        if (!address)
            address = co_await db.find_node_address_v6(node_id);
        if (address) {
            NodeAddress node_address{
                boost::asio::ip::udp::endpoint(address->ip, address->port_disc),
                address->port_rlpx,
            };
            node_addresses.insert({node_id, std::move(node_address)});
        }
    }

    auto& recipient = sender_endpoint;
    NeighborsMessage neighbors{
        std::move(node_addresses),
        make_message_expiration(),
    };

    try {
        co_await sender.send_neighbors(std::move(neighbors), recipient);
    } catch (const boost::system::system_error& ex) {
        if (ex.code() == boost::system::errc::operation_canceled)
            throw;
        log::Warning("disc_v4") << "FindNodeHandler::handle failed to reply"
                                << " to " << recipient
                                << " due to exception: " << ex.what();
    }
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
