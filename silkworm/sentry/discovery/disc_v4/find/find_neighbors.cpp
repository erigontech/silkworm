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

#include "find_neighbors.hpp"

#include <chrono>
#include <map>
#include <stdexcept>
#include <variant>

#include <boost/asio/this_coro.hpp>

#include <silkworm/infra/concurrency/awaitable_future.hpp>
#include <silkworm/infra/concurrency/awaitable_wait_for_one.hpp>
#include <silkworm/infra/concurrency/timeout.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/ip_classify.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/message_expiration.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_address.hpp>
#include <silkworm/sentry/discovery/disc_v4/common/node_distance.hpp>

namespace silkworm::sentry::discovery::disc_v4::find {

Task<size_t> find_neighbors(
    EccPublicKey node_id,
    std::optional<boost::asio::ip::udp::endpoint> endpoint_opt,
    EccPublicKey local_node_id,
    MessageSender& message_sender,
    boost::signals2::signal<void(NeighborsMessage, EccPublicKey)>& on_neighbors_signal,
    node_db::NodeDb& db) {
    using namespace std::chrono_literals;
    using namespace concurrency::awaitable_wait_for_one;

    boost::asio::ip::udp::endpoint endpoint;
    if (endpoint_opt) {
        endpoint = *endpoint_opt;
    } else {
        auto address = co_await db.find_node_address_v4(node_id);
        if (!address) {
            throw std::runtime_error("find_neighbors: node address not found");
        }
        endpoint = boost::asio::ip::udp::endpoint(address->ip, address->port_disc);
    }

    auto executor = co_await boost::asio::this_coro::executor;
    concurrency::AwaitablePromise<std::map<EccPublicKey, NodeAddress>> neighbors_promise{executor};
    auto neighbors_future = neighbors_promise.get_future();
    auto on_neighbors_handler = [&](NeighborsMessage message, EccPublicKey sender_node_id) {
        if ((sender_node_id == node_id) && !is_expired_message_expiration(message.expiration)) {
            neighbors_promise.set_value(std::move(message.node_addresses));
        }
    };

    boost::signals2::scoped_connection neighbors_subscription(on_neighbors_signal.connect(on_neighbors_handler));

    FindNodeMessage find_node_message{
        local_node_id,
        make_message_expiration(),
    };

    co_await message_sender.send_find_node(std::move(find_node_message), endpoint);

    std::map<EccPublicKey, NodeAddress> neighbors_node_addresses;
    try {
        neighbors_node_addresses = std::get<0>(co_await (neighbors_future.get_async() || concurrency::timeout(500ms)));
    } catch (const concurrency::TimeoutExpiredError&) {
        co_return 0;
    }

    for (auto& [neighbor_id, neighbor_node_address] : neighbors_node_addresses) {
        auto ip = neighbor_node_address.endpoint.address();
        if (ip_classify(ip) != IpAddressType::kRegular) {
            continue;
        }

        node_db::NodeAddress address{
            std::move(ip),
            neighbor_node_address.endpoint.port(),
            neighbor_node_address.port_rlpx,
        };

        auto distance = node_distance(node_id, local_node_id);

        co_await db.upsert_node_address(node_id, std::move(address));
        co_await db.update_distance(node_id, distance);
    }

    co_return neighbors_node_addresses.size();
}

}  // namespace silkworm::sentry::discovery::disc_v4::find
